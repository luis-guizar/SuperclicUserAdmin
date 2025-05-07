FROM python:3.13-alpine

# Set the working directory
WORKDIR /app


RUN apk add --no-cache --virtual .build-deps build-base gcc musl-dev python3-dev && \
    # Add any other system dependencies needed by your Python packages here
    # e.g., postgresql-dev if using psycopg2
    apk add --no-cache libffi-dev openssl-dev cargo

# Copy only the requirements file first to leverage Docker cache
COPY requirements.txt .


RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Remove the build dependencies now that pip install is done
RUN apk del .build-deps

# Create a non-root user and group for security
RUN addgroup -S appuser && adduser -S appuser -G appuser

# Change ownership of the app directory to the new user
# Do this *before* switching user
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 3334

# Define environment variable placeholders (values provided at runtime)
ENV SUPABASE_URL=""
ENV SUPABASE_SERVICE_ROLE_KEY=""

# Command to run the application using uvicorn (robust version)
CMD ["python", "-m", "uvicorn", "SuperclicUserAdmin:app", "--host", "0.0.0.0", "--port", "3334"]