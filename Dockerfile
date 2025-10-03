# Use an official Python runtime as a parent image
FROM python:3.12-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /code

# Copy the current directory contents into the container at /code/
COPY . /code/

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt 

RUN apk add --no-cache \
        bash nginx supervisor \
    && mkdir -p /run/nginx


# Create non-root user
RUN addgroup -S -g 1010 bulkintel && \
    adduser  -S -u 1010 -G bulkintel bulkintel

RUN chown -R bulkintel:bulkintel /code

# Copy Nginx & Supervisor configs 
COPY nginx/default.conf /etc/nginx/nginx.conf
COPY ./supervisord.conf /etc/supervisord.conf
COPY ./entrypoint.sh /code/

RUN chmod +x /code/entrypoint.sh

ENTRYPOINT ["/code/entrypoint.sh"]

# CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

EXPOSE 80