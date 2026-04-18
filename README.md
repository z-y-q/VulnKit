# PenTest Tools v3.0.0

A comprehensive Chrome extension for penetration testing and security research, featuring modern architecture, AI-powered analysis, and enterprise-grade security tools.

## 🚀 Features

### Core Tools
- **Encoding Tools**: Base64, URL, HTML, Hex encoding/decoding
- **Hashing Tools**: SHA-256, SHA-1, SHA-512, MD5 generation
- **JWT Tools**: Parse, validate, and analyze JSON Web Tokens
- **JSON Tools**: Format, validate, and manipulate JSON data
- **Regex Tools**: Test and debug regular expressions
- **URL Tools**: Parse, validate, and security-analyze URLs
- **Generator Tools**: Password, UUID, random string generation

### Security Analysis
- **Network Scanner**: Port scanning and network reconnaissance
- **Vulnerability Scanner**: XSS, SQL injection, directory traversal detection
- **AI Analysis**: Machine learning-powered vulnerability detection
- **Content Security**: In-page security analysis and highlighting

### User Interface
- **Modern Popup**: Compact 420px interface with 7 tool categories
- **Professional Sidebar**: Full-screen workspace with 16 security tools
- **Responsive Design**: Mobile-friendly and accessible
- **Theme System**: Dark, light, and system theme support

## 🛠️ Installation

### From Chrome Web Store
1. Visit the Chrome Web Store
2. Search for "PenTest Tools"
3. Click "Add to Chrome"
4. Grant necessary permissions

### Manual Installation
1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked extension"
5. Select the project directory

## 📖 Usage

### Popup Interface
- Click the PenTest Tools icon in your browser toolbar
- Select a tool category from the navigation tabs
- Use the input fields to enter data
- Click action buttons to perform operations
- Copy results using the copy button

### Sidebar Interface
- Right-click on any page and select "Inspect"
- Click the PenTest Tools icon in the developer tools
- Select from 16 available security tools
- Use the workspace area for detailed analysis
- View results in the dedicated output panels

### Context Menu
- Right-click on selected text to encode/decode
- Right-click on links to analyze URLs
- Right-click on pages for security analysis

## 🏗️ Architecture

### Modern Tech Stack
- **TypeScript**: Full type safety and modern JavaScript features
- **ES6 Modules**: Clean module imports and exports
- **Webpack**: Professional build system with code splitting
- **CSS3**: Modern styling with CSS variables and animations

### Project Structure
```
pentest-tools/
├── src/
│   ├── core/           # Core application logic
│   ├── modules/        # Individual tool modules
│   ├── ui/             # UI components
│   ├── styles/         # CSS stylesheets
│   ├── popup/          # Popup interface
│   ├── sidebar/        # Sidebar interface
│   ├── background/     # Background service worker
│   ├── content/        # Content scripts
│   └── options/        # Options page
├── test/               # Test files
├── assets/             # Static assets
└── build/              # Build configuration
```

### Module System
- **CoreManager**: Application lifecycle management
- **ModuleManager**: Dynamic module loading and dependency management
- **EventBus**: Centralized event communication system
- **Component**: Reusable UI component base class

## 🔧 Development

### Prerequisites
- Node.js 16+ and npm
- Chrome 120+ for Manifest V3 support
- Basic knowledge of TypeScript and Chrome extensions

### Setup
```bash
# Clone the repository
git clone https://github.com/your-org/pentest-tools.git
cd pentest-tools

# Install dependencies
npm install

# Development mode
npm run dev

# Build for production
npm run build

# Run tests
npm test

# Lint code
npm run lint
```

### Development Workflow
1. Make changes to source code
2. Test using `npm run dev`
3. Run tests with `npm test`
4. Build with `npm run build`
5. Load unpacked extension in Chrome
6. Test functionality
7. Commit changes

### Testing
- **Unit Tests**: Individual module testing
- **Integration Tests**: Cross-module functionality testing
- **Performance Tests**: Response time and memory usage testing
- **Browser Tests**: Cross-browser compatibility testing

## 📊 Performance

### Benchmarks
- **Initialization**: < 500ms
- **Tool Operations**: < 100ms average
- **Memory Usage**: < 10MB runtime
- **Bundle Size**: < 2MB minified

### Optimization Features
- Code splitting and lazy loading
- Efficient DOM manipulation
- Memory leak prevention
- Performance monitoring

## 🔒 Security

### Features
- Content Security Policy (CSP) compliance
- Input validation and sanitization
- Secure coding practices
- OWASP guidelines adherence
- Regular security audits

### Permissions
- `activeTab`: Access current tab content
- `storage`: Save user preferences and history
- `scripting`: Inject content scripts
- `webNavigation`: Monitor navigation events
- `contextMenus`: Add context menu options

## 🌍 Browser Support

### Compatible Browsers
- Chrome 120+
- Edge 120+
- Firefox 115+ (with modifications)
- Safari 16+ (with modifications)

### Manifest V3
- Service worker background scripts
- Enhanced content security policies
- Improved security model
- Better performance characteristics

## 📚 Documentation

### API Documentation
- [Module API](./docs/api.md)
- [Component Reference](./docs/components.md)
- [Extension Architecture](./docs/architecture.md)

### User Guide
- [Getting Started](./docs/user-guide.md)
- [Tool Tutorials](./docs/tutorials.md)
- [Security Best Practices](./docs/security.md)

### Developer Guide
- [Contributing Guidelines](./docs/contributing.md)
- [Code Style Guide](./docs/style-guide.md)
- [Testing Guidelines](./docs/testing.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](./docs/contributing.md) for details.

### Development Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request

### Code Standards
- TypeScript strict mode
- ESLint configuration
- Prettier formatting
- 80%+ test coverage
- Comprehensive documentation

## 📝 Changelog

### v3.0.0 (Current)
- Complete rewrite with modern architecture
- TypeScript implementation
- New AI-powered vulnerability detection
- Enhanced user interfaces
- Performance optimizations
- Security improvements

### Previous Versions
- [v2.0.0](https://github.com/your-org/pentest-tools/releases/tag/v2.0.0)
- [v1.1.0](https://github.com/your-org/pentest-tools/releases/tag/v1.1.0)
- [v1.0.0](https://github.com/your-org/pentest-tools/releases/tag/v1.0.0)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP Foundation for security guidelines
- Chrome Extension documentation team
- Security researchers and penetration testers
- Open source contributors

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/pentest-tools/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/pentest-tools/discussions)
- **Email**: support@pentest-tools.com
- **Twitter**: [@pentesttools](https://twitter.com/pentesttools)

## 🔗 Related Projects

- [OWASP ZAP](https://github.com/zaproxy/zaproxy)
- [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload)
- [Nikto](https://github.com/sullo/nikto)
- [SQLMap](https://github.com/sqlmapproject/sqlmap)

---

**Built with ❤️ by the PenTest Tools Team**