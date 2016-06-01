// Configure module loader
System.config({
    
    baseURL: '/',
    
    defaultJSExtensions: true,
    
    paths: {
        'systemjs': 'node_modules/systemjs/dist/system.js',
        'system-polyfills': 'node_modules/systemjs/dist/system-polyfills.js',
        'es6-module-loader': 'node_modules/es6-module-loader/dist/es6-module-loader.js',
        'oidc-token-manager': 'node_modules/oidc-token-manager/dist/oidc-token-manager.js'
    },


    // Set paths for third-party libraries as modules
    //packageConfigPaths: ['node_modules/oidc-token-manager/package.json']
});