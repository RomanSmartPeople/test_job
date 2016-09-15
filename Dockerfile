FROM python:2.7
ENV PYTHONUNBUFFERED 1
RUN mkdir /example_project
WORKDIR /example_project
ADD requirements.txt /example_project/
RUN pip install -r requirements.txt
ADD . /example_project/
