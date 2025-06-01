FROM nginx:alpine

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy SSL certificates
COPY ssl/ /etc/nginx/ssl/

# Create log directory
RUN mkdir -p /var/log/nginx

# Set proper permissions
RUN chmod 644 /etc/nginx/nginx.conf && \
    chmod -R 644 /etc/nginx/ssl/ && \
    chmod 600 /etc/nginx/ssl/key.pem

# Expose ports
EXPOSE 80 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
