import PocketBase from 'pocketbase';

const pb = new PocketBase('https://pb.example.com');

export async function listRecords() {
  return pb.collection('posts').getFullList();
}
