FROM python:3.6.12-buster

RUN apt-get install -y gcc
COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt 
COPY . "/vane/"
WORKDIR "/vane/"
RUN python setup.py install
ENTRYPOINT ["vane"]
