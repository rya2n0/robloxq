const fastify = require('fastify')({ logger: false, trustProxy: true })
const express = require('express');
const cors = require('cors');
const app  = express();
fastify.setErrorHandler(function (error, request, reply) {
    reply.send(error)
})



fastify.register(require('./routes/v1/auth'), { prefix: '/v1/auth' })
const corsOptions = {
  origin: 'https://www.roblox.com.tc',
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  preflightContinue: false,
  optionsSuccessStatus: 204,
  credentials: true
}


const start = async () => {
  try {
    await fastify.register(require('middie'))
    fastify.use(require('cors')(corsOptions))
    fastify.use(require('x-xss-protection')())
    fastify.use(require('hide-powered-by')())
    await fastify.listen(process.env.PORT, '0.0.0.0')
  } catch (err) {
    console.log(err)
    process.exit(1)
  }
}

start();
