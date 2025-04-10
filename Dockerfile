FROM node:16

# Set timezone
RUN apt-get update && apt-get install -y tzdata
ENV TZ=America/New_York

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 5000
CMD ["npm", "start"]