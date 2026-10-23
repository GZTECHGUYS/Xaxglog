import { render, screen } from '@testing-library/react';
import axios from 'axios';
import App from './App';

jest.mock('axios');

beforeEach(() => {
  const stub = { data: { threats: [], alerts: [], services: [] } };
  axios.create = jest.fn(() => ({
    get:    jest.fn(() => Promise.resolve(stub)),
    post:   jest.fn(() => Promise.resolve(stub)),
    delete: jest.fn(() => Promise.resolve(stub)),
  }));
});

test('renders dashboard header', async () => {
  render(<App />);
  expect(await screen.findByText(/OSINT Threat Dashboard/i)).toBeInTheDocument();
});
