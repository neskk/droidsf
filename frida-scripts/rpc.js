function helloFunc() {
  return 'Hello from %script%';
}

rpc.exports = {
  hello: helloFunc,
  failPlease: function () {
    oops;
  }
};