document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('form') || document.getElementById('userForm');
  
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const nameInput = document.querySelector('input[type="text"]');
      const emailInput = document.querySelector('input[type="email"]');
      
      if (!nameInput || !emailInput) return;
      
      const name = nameInput.value;
      const email = emailInput.value;

      try {
        // Create Table if not exists
        await fetch('/api/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sql: "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT);"
          })
        });

        // Insert User Data
        const res = await fetch('/api/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sql: "INSERT INTO users (name, email) VALUES (?, ?);",
            args: [name, email]
          })
        });

        const data = await res.json();
        if (data.success) {
          alert('መረጃው በስኬት ተመዝግቧል!');
          form.reset();
        } else {
          alert('ስህተት ተፈጠረ፦ ' + data.error);
        }
      } catch (err) {
        alert('ከባክኤንድ ጋር መገናኘት አልተቻለም፦ ' + err.message);
      }
    });
  }
});
