from collections import OrderedDict


def wrap_lists_in_unordered_lists(iterable):
    """Recursively iterate over the contents of a iterable and wrap all lists elements into UnorderedList"""
    if type(iterable) == dict or type(iterable) == OrderedDict:
        for key, value in iterable.items():
            iterable[key] = wrap_lists_in_unordered_lists(value)
        return iterable
    elif type(iterable) == list:
        li = [wrap_lists_in_unordered_lists(element) for element in iterable]
        return UnorderedList(li)
    else:
        return iterable


class UnorderedList:
    """Wrapper for a list, used for equality assertion based on orderless elements occurrence."""

    def __init__(self, list):
        self.list = list

    def __eq__(self, other):
        li = list(self.list)
        try:
            for element in other:
                li.remove(element)
        except ValueError:
            return False
        return len(li) == 0
