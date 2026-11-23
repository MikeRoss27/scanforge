import { Client, Account } from 'appwrite';

const client = new Client()
  .setEndpoint('https://fra.cloud.appwrite.io/v1')
  .setProject('65abc123def456');

export const account = new Account(client);
