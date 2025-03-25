// Templates Test - XSS Vulnerabilities

// 1. Template Literal XSS (High severity)
function displayUserCard() {
  const userName = getParameterByName('user');
  const userRole = getParameterByName('role');
  
  // Vulnerable template literal usage
  const cardTemplate = `
    <div class="user-card">
      <h3>${userName}</h3>
      <span class="role">${userRole}</span>
      <button onclick="editUser('${userName}')">Edit</button>
    </div>
  `;
  
  // Direct insertion without sanitization
  document.getElementById('user-container').innerHTML = cardTemplate;
}

// 2. Client-Side Template Injection (High severity)
function renderHandlebarsTemplate() {
  const userData = {
    name: getParameterByName('name'),
    email: getParameterByName('email'),
    bio: getParameterByName('bio')
  };
  
  // Triple braces in Handlebars don't escape HTML (vulnerable)
  const template = `
    <script id="user-template" type="text/x-handlebars-template">
      <div class="profile">
        <h2>{{name}}</h2>
        <p class="email">{{email}}</p>
        <div class="bio">{{{bio}}}</div>
      </div>
    </script>
  `;
  
  // Compiling and rendering the template with user data
  const compiledTemplate = Handlebars.compile(template);
  const html = compiledTemplate(userData);
  document.getElementById('profile-container').innerHTML = html;
}

// 3. Angular Template Sanitization Bypass (Critical severity)
function unsafeAngularTemplate() {
  const userHtml = getParameterByName('content');
  
  // This bypasses Angular's built-in sanitization
  const component = {
    template: `
      <div [innerHTML]="userContent" class="user-content"></div>
    `,
    controller: function() {
      this.userContent = this.sanitizer.bypassSecurityTrustHtml(userHtml);
    }
  };
  
  return component;
}

// Helper function
function getParameterByName(name) {
  const url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
  const results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}