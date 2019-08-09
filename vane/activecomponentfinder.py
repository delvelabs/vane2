# Vane 2.0: A web application vulnerability assessment tool.
# Copyright (C) 2017-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


import asyncio
from hammertime.ruleset import RejectRequest, StopRequest
from hammertime.rules.deadhostdetection import OfflineHostException
from openwebvulndb.common.schemas import FileListGroupSchema
from os.path import join
from .filefetcher import FileFetcher
from asyncio.queues import Queue
from .utils import load_model_from_file


class ActiveComponentFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)
        self.components_file_list_group = None

    def load_components_identification_file(self, file_path, component_base_key, popular, vulnerable):
        file_names = self._get_file_names(file_path, component_base_key, popular, vulnerable)
        errors = []
        for file_name in file_names:
            file_list_group, _errors = load_model_from_file(file_name, FileListGroupSchema())
            if _errors:
                errors.extend(_errors)
            if self.components_file_list_group is None:
                self.components_file_list_group = file_list_group
            else:
                self._merge_to_file_list_group(file_list_group)
        return errors

    def get_component_file_list(self, component_key):
        for file_list in self.components_file_list_group.file_lists:
            if file_list.key == component_key:
                return file_list
        return None

    def _get_file_names(self, path, key, popular, vulnerable):
        base_name = join(path, "vane2_{0}%s_versions.json" % key)
        if not vulnerable and not popular:
            return [base_name.format("")]
        names = []
        if popular:
            names.append(base_name.format("popular_"))
        if vulnerable:
            names.append(base_name.format("vulnerable_"))
        return names

    def _merge_to_file_list_group(self, file_list_group):
        for file_list in file_list_group.file_lists:
            if file_list.key not in (file_list.key for file_list in self.components_file_list_group.file_lists):
                self.components_file_list_group.file_lists.append(file_list)

    def enumerate_found(self):
        tasks_list = []

        for component_file_list in self.components_file_list_group.file_lists:
            if len(component_file_list.files) > 0:
                component_files_requests = self.file_fetcher.request_files(component_file_list.key, component_file_list)
                tasks_list.append(component_files_requests)

        return FoundComponentIterator(self.loop, tasks_list)


class FoundComponentIterator:

    def __init__(self, loop, components_file_request_list):
        self.loop = loop
        self.pending_tasks = components_file_request_list
        self._to_remove = None
        self.done = Queue(loop=self.loop)
        self.add_done_callback()

    def add_done_callback(self):
        for task in self.pending_tasks:
            task.add_done_callback(self.on_completion)

    def on_completion(self, task):
        self.pending_tasks.remove(task)
        self.done.put_nowait(task)

    async def cancel_pending_tasks(self):
        for task in self.pending_tasks:
            task.cancel()
        if len(self.pending_tasks):
            await asyncio.wait(self.pending_tasks)
        while not self.done.empty():
            task = self.done.get_nowait()
            try:
                task.result()
            except:
                pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        while len(self.pending_tasks) > 0 or not self.done.empty():
            try:
                future = await self.done.get()
                component_key, fetched_files = await future
                self._to_remove = future
                if len(fetched_files) > 0:
                    return {'key': component_key, 'files': fetched_files}
            except OfflineHostException:
                await self.cancel_pending_tasks()
                raise
            except (RejectRequest, StopRequest) as e:
                # Not fatal at all, just one of many
                pass
        raise StopAsyncIteration
