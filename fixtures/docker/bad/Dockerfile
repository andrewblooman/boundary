FROM node:latest
ENV API_KEY=FAKE-KEY-FOR-TESTS-000
RUN curl -sSL https://get.example.com/install.sh | sh
ADD https://example.com/tool.tar.gz /opt/
RUN chmod 777 /app
EXPOSE 22
EXPOSE 8080
CMD ["node", "server.js"]
