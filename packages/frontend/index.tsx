import React from 'react';
import ReactDOM from 'react-dom/client';
import { CaidoProvider } from '@caido/sdk-frontend';
import App from './App';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <React.StrictMode>
    <CaidoProvider>
      <App />
    </CaidoProvider>
  </React.StrictMode>
); 