# Use a lightweight NGINX alpine container to serve the static frontend assets
FROM nginx:alpine

# Clear the default NGINX contents
RUN rm -rf /usr/share/nginx/html/*

# Copy the frontend files to the web server root
COPY . /usr/share/nginx/html

# Expose port 80 (Docker compose maps this to port 3000 locally)
EXPOSE 80

# Start NGINX
CMD ["nginx", "-g", "daemon off;"]
