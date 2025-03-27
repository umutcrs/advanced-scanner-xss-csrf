const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// Test dosyalarını oku
const testFalsePositives = fs.readFileSync(path.join('test-cases', 'test-false-positives.js'), 'utf8');
const testTruePositives = fs.readFileSync(path.join('test-cases', 'test-true-positives.js'), 'utf8');
const testSubtleVuln = fs.readFileSync(path.join('test-cases', 'test-subtle-vulnerabilities.js'), 'utf8');
const testMinified = fs.readFileSync(path.join('test-cases', 'test-minified-code.js'), 'utf8');
const testCsrf = fs.readFileSync(path.join('test-cases', 'test-csrf-vulnerabilities.js'), 'utf8');

// Test sonuçları için dizin oluştur
if (!fs.existsSync('test-results')) {
  fs.mkdirSync('test-results');
}

// Her bir test için HTTP isteği yap
function runTest(testName, testCode) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({
      code: testCode
    });

    const options = {
      hostname: 'localhost',
      port: 5000,
      path: '/api/scan',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
      }
    };

    const req = http.request(options, (res) => {
      let responseData = '';

      res.on('data', (chunk) => {
        responseData += chunk;
      });

      res.on('end', () => {
        try {
          const result = JSON.parse(responseData);
          
          // Sonuçları kaydet
          fs.writeFileSync(
            path.join('test-results', `${testName}-result.json`),
            JSON.stringify(result, null, 2),
            'utf8'
          );
          
          console.log(`Test completed: ${testName} - Total vulnerabilities: ${result.vulnerabilities ? result.vulnerabilities.length : 0}`);
          resolve(result);
        } catch (err) {
          console.error(`Error parsing response for ${testName}:`, err);
          reject(err);
        }
      });
    });

    req.on('error', (error) => {
      console.error(`Error running test ${testName}:`, error);
      reject(error);
    });

    req.write(data);
    req.end();
  });
}

// Türe göre savunmasızlıkları say
function countByType(vulnerabilities) {
  if (!vulnerabilities) return {};
  
  const counts = {};
  vulnerabilities.forEach(vuln => {
    if (counts[vuln.type]) {
      counts[vuln.type]++;
    } else {
      counts[vuln.type] = 1;
    }
  });
  return counts;
}

// Tüm testleri çalıştır
async function runAllTests() {
  console.log('Starting tests...');
  
  try {
    // Yanlış pozitif testleri
    const falsePositivesResult = await runTest('false-positives', testFalsePositives);
    
    // Gerçek pozitif testleri
    const truePositivesResult = await runTest('true-positives', testTruePositives);
    
    // Gizli güvenlik açıkları testleri
    const subtleVulnResult = await runTest('subtle-vulnerabilities', testSubtleVuln);
    
    // Sıkıştırılmış kod testleri
    const minifiedResult = await runTest('minified-code', testMinified);
    
    // CSRF testleri
    const csrfResult = await runTest('csrf-vulnerabilities', testCsrf);
    
    // Özet rapor hazırla
    const summary = {
      falsePositives: {
        total: falsePositivesResult.vulnerabilities ? falsePositivesResult.vulnerabilities.length : 0,
        byType: countByType(falsePositivesResult.vulnerabilities)
      },
      truePositives: {
        total: truePositivesResult.vulnerabilities ? truePositivesResult.vulnerabilities.length : 0,
        byType: countByType(truePositivesResult.vulnerabilities)
      },
      subtleVulnerabilities: {
        total: subtleVulnResult.vulnerabilities ? subtleVulnResult.vulnerabilities.length : 0,
        byType: countByType(subtleVulnResult.vulnerabilities)
      },
      minifiedCode: {
        total: minifiedResult.vulnerabilities ? minifiedResult.vulnerabilities.length : 0,
        byType: countByType(minifiedResult.vulnerabilities)
      },
      csrfVulnerabilities: {
        total: csrfResult.vulnerabilities ? csrfResult.vulnerabilities.length : 0,
        byType: countByType(csrfResult.vulnerabilities)
      }
    };
    
    fs.writeFileSync(
      path.join('test-results', 'summary.json'),
      JSON.stringify(summary, null, 2),
      'utf8'
    );
    
    console.log('All tests completed. Results saved in test-results directory.');
    console.log('Summary:', JSON.stringify(summary, null, 2));
    
    // Başarı oranı hesaplaması
    calculateSuccessRates(falsePositivesResult, truePositivesResult, subtleVulnResult, minifiedResult, csrfResult);
    
  } catch (err) {
    console.error('Test execution failed:', err);
  }
}

// Başarı oranlarını hesapla
function calculateSuccessRates(falsePositivesResult, truePositivesResult, subtleVulnResult, minifiedResult, csrfResult) {
  // False pozitif oranı (ne kadar düşük o kadar iyi)
  const falsePositiveCount = falsePositivesResult.vulnerabilities ? falsePositivesResult.vulnerabilities.length : 0;
  const falsePositiveRate = falsePositiveCount > 0 ? 
    `Yanlış pozitiflerde ${falsePositiveCount} tane uyarı var. İyileştirilmesi gerekiyor.` : 
    'Yanlış pozitif testlerde hiç uyarı yok. Mükemmel!';
  
  // True pozitif oranı (ne kadar yüksek o kadar iyi)
  // Toplam 15 güvenlik açığı var bu dosyada
  const truePositiveCount = truePositivesResult.vulnerabilities ? truePositivesResult.vulnerabilities.length : 0;
  const truePositiveRate = (truePositiveCount / 15) * 100;
  
  // Gizli güvenlik açıkları tespit oranı (ne kadar yüksek o kadar iyi)
  // Toplam 10 gizli güvenlik açığı var bu dosyada
  const subtleVulnCount = subtleVulnResult.vulnerabilities ? subtleVulnResult.vulnerabilities.length : 0;
  const subtleVulnRate = (subtleVulnCount / 10) * 100;
  
  // Minified kod tespit oranı (ne kadar yüksek o kadar iyi)
  // Toplam 10 güvenlik açığı var bu dosyada
  const minifiedCount = minifiedResult.vulnerabilities ? minifiedResult.vulnerabilities.length : 0;
  const minifiedRate = (minifiedCount / 10) * 100;
  
  // CSRF tespit oranı (ne kadar yüksek o kadar iyi)
  // Toplam 10 CSRF güvenlik açığı var bu dosyada
  const csrfCount = csrfResult.vulnerabilities ? csrfResult.vulnerabilities.length : 0;
  const csrfRate = (csrfCount / 10) * 100;
  
  // Genel başarı oranı
  const overallDetectionRate = (truePositiveRate + subtleVulnRate + minifiedRate + csrfRate) / 4;
  
  const summary = {
    falsePositiveRate: falsePositiveRate,
    truePositiveRate: `Açık güvenlik zaafiyetlerinin tespit oranı: ${truePositiveRate.toFixed(2)}%`,
    subtleVulnRate: `Gizli güvenlik açıklarının tespit oranı: ${subtleVulnRate.toFixed(2)}%`,
    minifiedRate: `Sıkıştırılmış koddaki güvenlik açıklarının tespit oranı: ${minifiedRate.toFixed(2)}%`,
    csrfRate: `CSRF güvenlik açıklarının tespit oranı: ${csrfRate.toFixed(2)}%`,
    overallRate: `Genel başarı oranı: ${overallDetectionRate.toFixed(2)}%`
  };
  
  console.log('\n--- TEST SONUÇLARI ---');
  console.log(summary.falsePositiveRate);
  console.log(summary.truePositiveRate);
  console.log(summary.subtleVulnRate);
  console.log(summary.minifiedRate);
  console.log(summary.csrfRate);
  console.log(summary.overallRate);
  
  fs.writeFileSync(
    path.join('test-results', 'success-rates.json'),
    JSON.stringify(summary, null, 2),
    'utf8'
  );
}

// Tüm testleri başlat
runAllTests();