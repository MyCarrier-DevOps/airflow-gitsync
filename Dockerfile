FROM bitnami/git:2.39.1-debian-11-r6

RUN apt-get update && apt-get install jq python3 python3-pip -y && pip install jwt 
COPY jwt.py .