const request = require('supertest');
const app = require('../server');

describe('Unit Tests cho Web App', () => {
  it('GET / trả về status 200', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
    expect(res.body.status).toEqual('OK');
  });
});