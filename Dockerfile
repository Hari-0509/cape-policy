FROM python:3.12-slim

WORKDIR /cape-policy

COPY backend/requirements.txt /cape-policy/backend/requirements.txt

RUN pip install --no-cache-dir -r /cape-policy/backend/requirements.txt

COPY backend /cape-policy/backend
COPY test-policies /cape-policy/test-policies
COPY tests /cape-policy/tests
COPY README.md /cape-policy/README.md

WORKDIR /cape-policy/backend

CMD ["bash"]

