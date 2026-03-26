FROM nginx:alpine

# Clear the default NGINX contents
RUN rm -rf /usr/share/nginx/html/*

# Copy the frontend files to the web server root
COPY . /usr/share/nginx/html

# Set lateralshield-landing.html as the explicit index page
RUN printf 'server {\n  listen 80;\n  root /usr/share/nginx/html;\n  index lateralshield-landing.html;\n  location / { try_files $uri $uri/ /lateralshield-landing.html; }\n}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
