// src/firebase.js
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyDduIwzsZTAfwjgT6aVuApfGRCr7uqz_9o",
  authDomain: "sakhi-72ea4.firebaseapp.com",
  projectId: "sakhi-72ea4",
  storageBucket: "sakhi-72ea4.firebasestorage.app",
  messagingSenderId: "110481934606",
  appId: "1:110481934606:web:597ceadd456e7a9975ef5f",
  measurementId: "G-T9W250374S"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
