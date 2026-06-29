// Minimal HTTP function for the Ventra lab. Exercised by the cloud_functions and
// api_gateway collectors — every invocation produces a Cloud Logging entry.
exports.helloHttp = (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.status(200).send('ventra lab function ok');
};
