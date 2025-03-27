const fs = require('fs');
const path = require('path');
const http = require('http');

// Test dosyalarını oku
const truePositivesAdvanced = fs.readFileSync(path.join('test-advanced', 'true-positives-advanced.js'), 'utf8');
const falsePositivesAdvanced = fs.readFileSync(path.join('test-advanced', 'false-positives-advanced.js'), 'utf8');
const obfuscatedCode = fs.readFileSync(path.join('test-advanced', 'obfuscated-code.js'), 'utf8');
const csrfComplex = fs.readFileSync(path.join('test-advanced', 'csrf-complex.js'), 'utf8');
const browserExtensionPatterns = fs.readFileSync(path.join('test-advanced', 'browser-extension-patterns.js'), 'utf8');

// Test sonuçları için dizin oluştur
if (!fs.existsSync('test-advanced-results')) {
  fs.mkdirSync('test-advanced-results');
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
            path.join('test-advanced-results', `${testName}-result.json`),
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
  console.log('Starting advanced tests...');
  
  try {
    // Gelişmiş doğru pozitif testleri
    const truePositivesResult = await runTest('true-positives-advanced', truePositivesAdvanced);
    
    // Gelişmiş yanlış pozitif testleri
    const falsePositivesResult = await runTest('false-positives-advanced', falsePositivesAdvanced);
    
    // Minify/obfuscated kod testleri
    const obfuscatedResult = await runTest('obfuscated-code', obfuscatedCode);
    
    // Kompleks CSRF testleri
    const csrfResult = await runTest('csrf-complex', csrfComplex);
    
    // Tarayıcı uzantıları testleri
    const browserExtResult = await runTest('browser-extension-patterns', browserExtensionPatterns);
    
    // Özet rapor hazırla
    const summary = {
      truePositivesAdvanced: {
        total: truePositivesResult.vulnerabilities ? truePositivesResult.vulnerabilities.length : 0,
        expected: 15, // Bu dosyada 15 açık var
        detectionRate: truePositivesResult.vulnerabilities ? 
          (truePositivesResult.vulnerabilities.length / 15) * 100 : 0,
        byType: countByType(truePositivesResult.vulnerabilities)
      },
      falsePositivesAdvanced: {
        total: falsePositivesResult.vulnerabilities ? falsePositivesResult.vulnerabilities.length : 0,
        expected: 0, // Bu dosyada 0 açık olmalı (hepsi güvenli kod)
        falsePositiveRate: falsePositivesResult.vulnerabilities ? 
          falsePositivesResult.vulnerabilities.length : 0,
        byType: countByType(falsePositivesResult.vulnerabilities)
      },
      obfuscatedCode: {
        total: obfuscatedResult.vulnerabilities ? obfuscatedResult.vulnerabilities.length : 0,
        expected: 15, // Bu dosyada 15 açık var
        detectionRate: obfuscatedResult.vulnerabilities ? 
          (obfuscatedResult.vulnerabilities.length / 15) * 100 : 0,
        byType: countByType(obfuscatedResult.vulnerabilities)
      },
      csrfComplex: {
        total: csrfResult.vulnerabilities ? csrfResult.vulnerabilities.length : 0,
        expected: 15, // Bu dosyada 15 CSRF açığı var
        detectionRate: csrfResult.vulnerabilities ? 
          (csrfResult.vulnerabilities.length / 15) * 100 : 0,
        byType: countByType(csrfResult.vulnerabilities)
      },
      browserExtensionPatterns: {
        total: browserExtResult.vulnerabilities ? browserExtResult.vulnerabilities.length : 0,
        expectedVulnerable: 10, // İlk 10 fonksiyon açık içeriyor
        expectedSafe: 10, // Son 10 fonksiyon güvenli olmalı
        detectionRate: browserExtResult.vulnerabilities ? 
          (browserExtResult.vulnerabilities.length / 10) * 100 : 0,
        byType: countByType(browserExtResult.vulnerabilities)
      }
    };
    
    fs.writeFileSync(
      path.join('test-advanced-results', 'summary.json'),
      JSON.stringify(summary, null, 2),
      'utf8'
    );
    
    console.log('All advanced tests completed. Results saved in test-advanced-results directory.');
    
    // Başarı oranları raporu
    console.log('\n--- ADVANCED TEST SONUÇLARI ---');
    console.log(`Gelişmiş True Positive Tespit Oranı: ${summary.truePositivesAdvanced.detectionRate.toFixed(2)}%`);
    console.log(`Gelişmiş False Positive Sayısı: ${summary.falsePositivesAdvanced.total}`);
    console.log(`Obfuscated/Minified Kod Tespit Oranı: ${summary.obfuscatedCode.detectionRate.toFixed(2)}%`);
    console.log(`Kompleks CSRF Tespit Oranı: ${summary.csrfComplex.detectionRate.toFixed(2)}%`);
    console.log(`Tarayıcı Uzantıları Tespit Oranı: ${summary.browserExtensionPatterns.detectionRate.toFixed(2)}%`);
    
    // Tespit edilen örüntülerin ayrıntılı raporu
    console.log('\n--- TESPİT EDİLEN ÖRÜNTÜLER ---');
    
    if (truePositivesResult.vulnerabilities && truePositivesResult.vulnerabilities.length > 0) {
      console.log('\nGelişmiş True Positive Tespitler:');
      const truePositiveTypes = countByType(truePositivesResult.vulnerabilities);
      for (const type in truePositiveTypes) {
        console.log(`  ${type}: ${truePositiveTypes[type]}`);
      }
    }
    
    if (falsePositivesResult.vulnerabilities && falsePositivesResult.vulnerabilities.length > 0) {
      console.log('\nGelişmiş False Positive Tespitler (Bu liste boş olmalı):');
      const falsePositiveTypes = countByType(falsePositivesResult.vulnerabilities);
      for (const type in falsePositiveTypes) {
        console.log(`  ${type}: ${falsePositiveTypes[type]}`);
      }
    }
    
    if (obfuscatedResult.vulnerabilities && obfuscatedResult.vulnerabilities.length > 0) {
      console.log('\nObfuscated/Minified Kod Tespitler:');
      const obfuscatedTypes = countByType(obfuscatedResult.vulnerabilities);
      for (const type in obfuscatedTypes) {
        console.log(`  ${type}: ${obfuscatedTypes[type]}`);
      }
    }
    
    if (csrfResult.vulnerabilities && csrfResult.vulnerabilities.length > 0) {
      console.log('\nKompleks CSRF Tespitler:');
      const csrfTypes = countByType(csrfResult.vulnerabilities);
      for (const type in csrfTypes) {
        console.log(`  ${type}: ${csrfTypes[type]}`);
      }
    }
    
    if (browserExtResult.vulnerabilities && browserExtResult.vulnerabilities.length > 0) {
      console.log('\nTarayıcı Uzantıları Tespitler:');
      const browserExtTypes = countByType(browserExtResult.vulnerabilities);
      for (const type in browserExtTypes) {
        console.log(`  ${type}: ${browserExtTypes[type]}`);
      }
    }
    
    // Genel başarı oranı hesapla
    const overallDetectionRate = (
      summary.truePositivesAdvanced.detectionRate +
      summary.obfuscatedCode.detectionRate +
      summary.csrfComplex.detectionRate +
      summary.browserExtensionPatterns.detectionRate
    ) / 4;
    
    const falsePositiveScore = summary.falsePositivesAdvanced.total === 0 ? 100 : 
      Math.max(0, 100 - (summary.falsePositivesAdvanced.total * 10));
    
    console.log('\n--- GENEL SONUÇ ---');
    console.log(`Ortalama Tespit Oranı: ${overallDetectionRate.toFixed(2)}%`);
    console.log(`False Positive Skoru: ${falsePositiveScore.toFixed(2)}%`);
    console.log(`Genel Başarı Puanı: ${((overallDetectionRate * 0.7) + (falsePositiveScore * 0.3)).toFixed(2)}%`);
    
  } catch (err) {
    console.error('Test execution failed:', err);
  }
}

// Tüm gelişmiş testleri başlat
runAllTests();