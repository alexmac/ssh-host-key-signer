FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt ${LAMBDA_TASK_ROOT}
RUN pip install -r requirements.txt

COPY *.py ${LAMBDA_TASK_ROOT}
COPY host_key_signer ${LAMBDA_TASK_ROOT}/host_key_signer

CMD [ "ssh_host_key_signer.handler" ]
