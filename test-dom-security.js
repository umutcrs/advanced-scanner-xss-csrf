// DOM Security Tests - XSS Vulnerabilities

// 1. DOM Clobbering Vulnerability (Medium severity)
function loadUserProfile() {
  // Vulnerable: Uses DOM property names as IDs, can be clobbered
  const nameElement = document.getElementById('name');
  const roleElement = document.getElementById('role');
  
  // Check if elements exist
  if (nameElement) {
    document.getElementById('user-welcome').textContent = 'Welcome, ' + nameElement.value;
  }
  
  // More DOM Clobbering opportunities
  const formElement = document.getElementById('forms'); // 'forms' is a DOM property
  const lengthElement = document.getElementById('length'); // 'length' is a DOM property
  
  // Using these elements without type checking
  if (formElement) {
    document.getElementById('form-container').appendChild(formElement);
  }
}

// 2. Sanitization Bypass (Critical severity)
function renderFormattedContent() {
  const userContent = getUserContent();
  
  // DANGEROUS: Bypassing DOMPurify with ALLOW_SCRIPT option
  const cleanHtml = DOMPurify.sanitize(userContent, {
    ALLOW_SCRIPT: true, // This defeats the purpose of sanitization!
    ALLOW_HTML: true
  });
  
  document.getElementById('formatted-content').innerHTML = cleanHtml;
}

// 3. Angular Security Bypass (Critical severity)
function createAngularComponent() {
  return {
    controller: function($scope, $sanitize) {
      $scope.userHtml = getUserContent();
      
      // DANGEROUS: Deliberately bypassing Angular's sanitization
      $scope.trustedHtml = this.sanitizer.bypassSecurityTrustHtml($scope.userHtml);
      $scope.trustedScript = this.sanitizer.bypassSecurityTrustScript($scope.userHtml);
      $scope.trustedResourceUrl = this.sanitizer.bypassSecurityTrustResourceUrl(getUserProvidedUrl());
    },
    template: `
      <div ng-bind-html="trustedHtml"></div>
      <script ng-bind="trustedScript"></script>
      <iframe ng-src="trustedResourceUrl"></iframe>
    `
  };
}

// 4. Mutation XSS vulnerability (High severity)
function copyContentBetweenElements() {
  // Get HTML from one element (potentially contains malicious markup)
  const sourceHtml = document.getElementById('user-content-source').innerHTML;
  
  // Mutation XSS vulnerability: Moving HTML between DOM elements
  // Browser parsing can transform seemingly safe HTML into executable scripts
  document.getElementById('user-content-target').innerHTML = sourceHtml;
}

// Helper functions
function getUserContent() {
  return localStorage.getItem('user-content') || '';
}

function getUserProvidedUrl() {
  return new URL(location.hash.substring(1) || 'https://example.com').toString();
}