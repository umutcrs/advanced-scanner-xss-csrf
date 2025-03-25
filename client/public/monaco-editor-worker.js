/**
 * This is a simple worker implementation for Monaco Editor
 * It acts as a proxy to load the main worker
 */
self.MonacoEnvironment = {
  baseUrl: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.36.1/min/'
};

importScripts('https://cdn.jsdelivr.net/npm/monaco-editor@0.36.1/min/vs/base/worker/workerMain.js');