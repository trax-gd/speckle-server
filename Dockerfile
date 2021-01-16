FROM mhart/alpine-node:12
# Create app directory
WORKDIR /app

# Bundle app source
COPY . .

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

RUN npm run build

FROM mhart/alpine-node:slim-12

# If possible, run your container using `docker run --init`
# Otherwise, you can use `tini`:
# RUN apk add --no-cache tini
# ENTRYPOINT ["/sbin/tini", "--"]

WORKDIR /app
COPY --from=0 /app .
COPY . .

EXPOSE 3000

WORKDIR /app/packages/server

CMD [ "node", "./bin/www" ]

# `docker build -t sbreslav/speckle-server .`
# `docker images` will list your images
# `docker run -p 80:80 -d sbreslav/speckle-server `