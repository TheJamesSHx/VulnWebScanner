"""Directory and file bruteforce scanner."""

import asyncio
from typing import Dict, List, Set
from urllib.parse import urljoin
from loguru import logger
import os


class DirectoryBrute:
    """Bruteforce directories and files on web servers."""

    def __init__(self, async_scanner, config: Dict = None):
        """Initialize directory bruteforcer.
        
        Args:
            async_scanner: AsyncScanner instance
            config: Configuration dictionary
        """
        self.scanner = async_scanner
        self.config = config or {}
        self.extensions = self.config.get('extensions', ['.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.txt'])
        self.found_paths: Set[str] = set()

    async def bruteforce(self, base_url: str, wordlist_path: str = None, 
                        extensions: List[str] = None) -> Dict:
        """Bruteforce directories and files.
        
        Args:
            base_url: Base URL to scan
            wordlist_path: Path to wordlist file
            extensions: File extensions to try
            
        Returns:
            Dictionary with discovered paths
        """
        logger.info(f"Starting directory bruteforce on {base_url}")
        
        if extensions is None:
            extensions = self.extensions
        
        # Load wordlist
        wordlist = self._load_wordlist(wordlist_path)
        
        if not wordlist:
            logger.warning("No wordlist provided, using default common paths")
            wordlist = self._get_default_wordlist()
        
        # Generate URLs to test
        urls_to_test = self._generate_urls(base_url, wordlist, extensions)
        
        logger.info(f"Testing {len(urls_to_test)} paths...")
        
        # Test URLs concurrently
        results = await self._test_urls(urls_to_test)
        
        # Organize results
        output = {
            'base_url': base_url,
            'total_tested': len(urls_to_test),
            'found': len(results['found']),
            'paths': sorted(results['found']),
            'interesting': sorted(results['interesting'])
        }
        
        logger.success(f"Directory bruteforce completed: {len(results['found'])} paths discovered")
        
        return output

    def _load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load wordlist from file.
        
        Args:
            wordlist_path: Path to wordlist file
            
        Returns:
            List of words
        """
        if not wordlist_path:
            return []
        
        try:
            if os.path.exists(wordlist_path):
                with open(wordlist_path, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
                logger.debug(f"Loaded {len(words)} entries from {wordlist_path}")
                return words
        except Exception as e:
            logger.error(f"Failed to load wordlist: {str(e)}")
        
        return []

    def _get_default_wordlist(self) -> List[str]:
        """Get default common paths.
        
        Returns:
            List of common paths
        """
        return [
            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
            'backup', 'backups', 'test', 'dev', 'old', 'new', 'temp',
            'api', 'v1', 'v2', 'graphql', 'rest',
            'config', 'configuration', 'settings', 'setup',
            'upload', 'uploads', 'files', 'images', 'img', 'assets',
            'css', 'js', 'javascript', 'scripts', 'style', 'styles',
            'include', 'includes', 'inc',
            'logs', 'log', 'debug',
            'sql', 'database', 'db', 'mysql',
            'user', 'users', 'account', 'accounts',
            'password', 'passwords', 'passwd',
            'private', 'public', 'secret', 'secrets',
            'data', 'backup.sql', 'dump.sql', 'database.sql',
            '.git', '.svn', '.env', '.htaccess', '.htpasswd',
            'web.config', 'composer.json', 'package.json',
            'README.md', 'readme.txt', 'TODO', 'CHANGELOG',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'error', 'errors', '404', '500',
            'search', 'contact', 'about', 'help',
            'dashboard', 'panel', 'console',
            'cgi-bin', 'bin', 'src', 'source',
            'download', 'downloads',
            'content', 'wp-content', 'wp-includes',
            'install', 'installation', 'installer'
        ]

    def _generate_urls(self, base_url: str, wordlist: List[str], 
                      extensions: List[str]) -> List[str]:
        """Generate URLs to test.
        
        Args:
            base_url: Base URL
            wordlist: List of paths
            extensions: File extensions
            
        Returns:
            List of URLs to test
        """
        urls = []
        
        for word in wordlist:
            # Directory
            urls.append(urljoin(base_url, word + '/'))
            
            # File without extension
            urls.append(urljoin(base_url, word))
            
            # File with extensions
            for ext in extensions:
                urls.append(urljoin(base_url, word + ext))
        
        return urls

    async def _test_urls(self, urls: List[str]) -> Dict:
        """Test URLs for existence.
        
        Args:
            urls: List of URLs to test
            
        Returns:
            Dictionary with found and interesting paths
        """
        found = []
        interesting = []
        
        # Test URLs in batches
        batch_size = 50
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i+batch_size]
            
            # Test batch concurrently
            tasks = [self.scanner.head(url) for url in batch]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for url, response in zip(batch, responses):
                if isinstance(response, dict) and response.get('status'):
                    status = response['status']
                    
                    # Found (200, 301, 302, 401, 403)
                    if status in [200, 301, 302, 401, 403]:
                        found.append({
                            'url': url,
                            'status': status,
                            'length': response.get('length', 0)
                        })
                        
                        # Interesting files
                        if any(keyword in url.lower() for keyword in 
                               ['.git', '.env', 'config', 'backup', '.sql', 'password', 'secret']):
                            interesting.append({
                                'url': url,
                                'status': status,
                                'reason': 'Potentially sensitive file'
                            })
                        
                        # Admin panels
                        if any(keyword in url.lower() for keyword in 
                               ['admin', 'login', 'dashboard', 'panel', 'phpmyadmin']):
                            interesting.append({
                                'url': url,
                                'status': status,
                                'reason': 'Admin/authentication endpoint'
                            })
        
        return {
            'found': found,
            'interesting': interesting
        }

    async def find_backups(self, url: str) -> List[str]:
        """Find common backup file patterns.
        
        Args:
            url: Base URL or specific file URL
            
        Returns:
            List of found backup files
        """
        logger.info(f"Searching for backup files at {url}")
        
        backup_patterns = [
            '.bak', '.backup', '.old', '.orig', '.save', '.swp', '~',
            '.backup.zip', '.zip', '.tar.gz', '.sql', '.sql.gz'
        ]
        
        # If URL is a file, try backup variations
        if '.' in url.split('/')[-1]:
            base = url.rsplit('.', 1)[0]
            ext = url.rsplit('.', 1)[1]
            
            urls_to_test = [
                f"{url}.bak",
                f"{url}.old",
                f"{url}~",
                f"{base}.{ext}.bak",
                f"{base}_backup.{ext}",
                f"{base}_old.{ext}"
            ]
        else:
            urls_to_test = [f"{url}{pattern}" for pattern in backup_patterns]
        
        results = await self._test_urls(urls_to_test)
        return [item['url'] for item in results['found']]

    async def find_exposed_files(self, base_url: str) -> List[Dict]:
        """Find commonly exposed sensitive files.
        
        Args:
            base_url: Base URL to scan
            
        Returns:
            List of exposed files
        """
        sensitive_files = [
            '.env', '.env.local', '.env.production',
            '.git/config', '.git/HEAD', '.gitignore',
            '.svn/entries', '.svn/wc.db',
            'web.config', 'Web.config',
            '.htaccess', '.htpasswd',
            'wp-config.php', 'wp-config.php.bak',
            'config.php', 'configuration.php', 'settings.php',
            'database.yml', 'database.php',
            'phpinfo.php', 'info.php',
            'composer.json', 'composer.lock',
            'package.json', 'package-lock.json',
            'yarn.lock',
            'Dockerfile', 'docker-compose.yml',
            '.DS_Store',
            'error.log', 'access.log', 'debug.log',
            'backup.sql', 'dump.sql', 'database.sql',
            'README.md', 'CHANGELOG.md', 'TODO.txt'
        ]
        
        urls_to_test = [urljoin(base_url, f) for f in sensitive_files]
        results = await self._test_urls(urls_to_test)
        
        return results['found']