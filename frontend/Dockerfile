FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci || npm install

COPY . .

EXPOSE 3000

ENV HOST=0.0.0.0 \
    WATCHPACK_POLLING=true

CMD ["npm", "start"]
