FROM python:3.8
ENV PYTHONUNBUFFERED 1
RUN mkdir /accuknox_backend
WORKDIR /accuknox_backend
ADD requirements.txt /accuknox_backend/
RUN pip install --progress-bar off -r requirements.txt
ADD . /accuknox_backend/