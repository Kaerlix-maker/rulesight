export interface Example { id: string; label: string; rules: string }

export const EXAMPLES: Example[] = [
  {
    id: 'test-mode',
    label: 'Firebase "test mode"',
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Default rules from the Firebase console ("Start in test mode")
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2027, 1, 15);
    }
  }
}
`,
  },
  {
    id: 'startup',
    label: 'Typical startup app',
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function signedIn() {
      return request.auth != null;
    }

    function isAdmin() {
      return get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }

    // User profiles
    match /users/{userId} {
      allow read: if signedIn();
      allow create, update: if request.auth.uid == userId;
    }

    // Orders
    match /orders/{orderId} {
      allow read: if signedIn() && resource.data.ownerId == request.auth.uid;
      allow create: if signedIn();
      allow update: if signedIn() && resource.data.ownerId == request.auth.uid;
      allow delete: if isAdmin();
    }

    // Private notes per user
    match /notes/{uid}/items/{noteId} {
      allow read, write: if signedIn();
    }

    // Product catalogue
    match /products/{productId} {
      allow read;
      allow write: if isAdmin();
    }
  }
}
`,
  },
  {
    id: 'secure',
    label: 'Secure reference',
    rules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function signedIn() { return request.auth != null; }
    function isOwner(uid) { return signedIn() && request.auth.uid == uid; }
    function isAdmin() { return signedIn() && request.auth.token.admin == true; }

    match /users/{userId} {
      allow read: if isOwner(userId) || isAdmin();
      allow create: if isOwner(userId)
        && request.resource.data.keys().hasOnly(['name', 'avatar'])
        && request.resource.data.name is string
        && request.resource.data.name.size() < 60;
      allow update: if isOwner(userId)
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['name', 'avatar']);
      allow delete: if false;
    }

    match /posts/{postId} {
      allow read: if true;
      allow create: if signedIn()
        && request.resource.data.authorId == request.auth.uid
        && request.resource.data.title is string
        && request.resource.data.title.size() < 200;
      allow update: if signedIn()
        && resource.data.authorId == request.auth.uid
        && request.resource.data.authorId == resource.data.authorId;
      allow delete: if isAdmin();
    }
  }
}
`,
  },
];
