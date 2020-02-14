#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 *
 * LamiaOy Magento 2 Magevulndb Standalone Audit — NOTICE OF LICENSE
 *
 * This source file is released under GPLv3 license by copyright holders.
 * Please see LICENSE file for more specific licensing terms.
 * @copyright 2019-2020 (c) Lamia Oy
 * @author Niko Granö <niko@lamia.fi>
 *
 */

namespace LamiaOy\Magento2\Framework {
    if (!file_exists(getcwd()."/vendor/magento/framework/AppInterface.php")) {
        echo 'Working directory must be Magento 2 root.';
        die(1);
    }

    require_once getcwd()."/vendor/magento/framework/AppInterface.php";
    require_once getcwd()."/vendor/magento/framework/App/Bootstrap.php";
    final class Application implements \Magento\Framework\AppInterface {
        public function launch()
        {
            // We want leave this empty. Nothing to do.
            return null;
        }

        public function catchException(\Magento\Framework\App\Bootstrap $bootstrap, \Exception $exception)
        {
            // Just pass to have control to Bootstrap.
            return false;
        }
    }
}

namespace LamiaOy\Magento2\Blacklist
{
    final class Entry {

        /**
         * @var string
         */
        private $moduleName;
        /**
         * @var string
         */
        private $currentVersion;
        /**
         * @var string
         */
        private $fixedIn;
        /**
         * @var string
         */
        private $route;
        /**
         * @var string
         */
        private $frontName;
        /**
         * @var string
         */
        private $credit;
        /**
         * @var string
         */
        private $updateUrl;

        public function __construct(
            string $moduleName,
            string $currentVersion,
            string $fixedIn,
            string $route,
            string $frontName,
            string $credit,
            string $updateUrl
        ) {
            $this->moduleName = $moduleName;
            $this->currentVersion = $currentVersion;
            $this->fixedIn = $fixedIn;
            $this->route = $route;
            $this->frontName = $frontName;
            $this->credit = $credit;
            $this->updateUrl = $updateUrl;
        }

        /**
         * @return string
         */
        public function getModuleName(): string
        {
            return $this->moduleName;
        }

        /**
         * @return string
         */
        public function getCurrentVersion(): string
        {
            return $this->currentVersion;
        }

        /**
         * @return string
         */
        public function getFixedIn(): string
        {
            return $this->fixedIn;
        }

        /**
         * @return string
         */
        public function getRoute(): string
        {
            return $this->route;
        }

        /**
         * @return string
         */
        public function getFrontName(): string
        {
            return $this->frontName;
        }

        /**
         * @return string
         */
        public function getCredit(): string
        {
            return $this->credit;
        }

        /**
         * @return string
         */
        public function getUpdateUrl(): string
        {
            return $this->updateUrl;
        }

        /**
         * @return bool
         */
        public function isModuleDetected(): bool
        {
            $version = $this->getCurrentVersion();
            return !empty($version);
        }

        /**
         * @return bool
         */
        public function isModuleVulnerable(): bool
        {
            if (!$this->isModuleDetected()) {
                return false;
            }
            if (!$this->getFixedIn()) {
                return true;
            }
            if (version_compare($this->getCurrentVersion(), $this->getFixedIn(), '>=')) {
                return false;
            }
            return true;
        }
    }

    final class Version {
        /**
         * @var \Magento\Framework\Module\ModuleListInterface
         */
        private $moduleList;

        /**
         * @var \Magento\Framework\Component\ComponentRegistrar
         */
        private $componentRegistrar;

        public function __construct(
            \Magento\Framework\Module\ModuleListInterface $moduleList,
            \Magento\Framework\Component\ComponentRegistrar $componentRegistrar
        ) {
            $this->moduleList = $moduleList;
            $this->componentRegistrar = $componentRegistrar;
        }

        /**
         * Get the installed version of the given module tag (if any).
         *
         * @param string $moduleName
         * @return string
         */
        public function getModuleVersion(string $moduleName): string
        {
            if ($version = $this->loadVersionFromComposer($moduleName)) {
                return $version;
            }
            return $this->loadVersionFromModuleXml($moduleName);
        }
        /**
         * @param string $moduleName
         * @return string
         */
        protected function loadVersionFromComposer(string $moduleName): string
        {
            $modulePath = $this->componentRegistrar->getPath('module', $moduleName);
            if (empty($modulePath)) {
                return '';
            }
            $composerFile = $modulePath . '/composer.json';
            if (!file_exists($composerFile) || !is_readable($composerFile)) {
                return '';
            }
            $composerContent = file_get_contents($composerFile);
            if (empty($composerContent)) {
                return '';
            }
            $composerData = json_decode($composerContent, true);
            if (!isset($composerData['version'])) {
                return '';
            }
            return (string)$composerData['version'];
        }
        /**
         * @param string $moduleName
         * @return string
         */
        protected function loadVersionFromModuleXml(string $moduleName): string
        {
            $module = $this->moduleList->getOne($moduleName);
            if (isset($module['setup_version'])) {
                return $module['setup_version'];
            }
            return '';
        }
    }

    final class Scanner {
        /**
         * CSV list of vulnerable extensions
         */
        private const BLACKLIST_URL = 'https://raw.githubusercontent.com/gwillem/magevulndb/master/magento2-vulnerable-extensions.csv';

        /**
         * @var Entry[]
         */
        private $entries = [];

        /**
         * @var Version
         */
        private $moduleVersion;

        /**
         * Blacklist constructor.
         *
         * @param Version $moduleVersion
         */
        public function __construct(
            Version $version
        ) {
            $this->moduleVersion = $version;
        }

        /**
         * Check if this list has vulnerable extensions
         *
         * @return bool
         */
        public function hasEntries()
        {
            return (bool)$this->getEntries();
        }
        /**
         * Get a list of vulnerable extensions
         *
         * @return Entry[]
         */
        public function getEntries(): array
        {
            if (count($this->entries) > 0) {
                return $this->entries;
            }
            if (($handle = fopen(self::BLACKLIST_URL, "r")) !== false) {
                while (($data = fgetcsv($handle, 1000, ",")) !== false) {
                    if ($data[0] === 'Name') {
                        continue;
                    }
                    $this->entries[] = new Entry(
                        (string)$data[0],
                        $this->moduleVersion->getModuleVersion((string)$data[0]),
                        (string)$data[1],
                        (string)$data[2],
                        $this->getFrontnameFromRoute((string)$data[2]),
                        (string)$data[3],
                        (string)$data[4]
                    );
                }
                fclose($handle);
            }
            return $this->entries;
        }
        /**
         * Get the frontname from the given (assumed) Magento route URL.
         *
         * @param string $route
         * @return string
         */
        protected function getFrontnameFromRoute(string $route): string
        {
            // Strip off any leading index.php and slashes. A frontname shouldn't contain either.
            $route = str_replace('index.php', '', $route);
            $route = trim($route, '/?');
            // If this looks like a multi-part route, the frontname is the first part.
            if (strpos($route, '/') !== false) {
                $route = substr($route, 0, strpos($route, '/'));
            }
            return $route;
        }
    }

    final class Parser {
        /**
         * @var Entry
         */
        private $entry;

        public function __construct(Entry $entry)
        {
            $this->entry = $entry;
        }

        /**
         * @return void
         * @throws AuditFailedException
         */
        public function isVulnerable(): void
        {
            $this->checkModule();
            $this->checkRoute();
        }

        private function checkModule(): void
        {
            if ($this->entry->isModuleVulnerable()) {
                throw new AuditFailedException($this->entry, AuditFailedException::TYPE_MODULE);
            }
        }

        private function checkRoute(): void
        {
            $module = $this->getModuleByRoute($this->entry->getFrontName());

            // No match if there's no module matching the frontname
            if (empty($module)) {
                return;
            }

            // No match if we know what module it is for
            // Those will match by module name, if they're related.
            if ($this->entry->getModuleName() !== '?' && !empty($this->entry->getModuleName())) {
                return;
            }

            throw new AuditFailedException($this->entry, AuditFailedException::TYPE_ROUTE);
        }

        private function getModuleByRoute(string $frontName): string
        {
            $om = \Magento\Framework\App\ObjectManager::getInstance();
            $state = $om->get(\Magento\Framework\App\State::class);
            /** @var \Magento\Framework\App\State $state */
            try {
                $state->setAreaCode('frontend');
            } catch (\Magento\Framework\Exception\LocalizedException $e) {}

            /** @var \Magento\Framework\App\Route\ConfigInterface $routeConfig */
            $routeConfig = $om->get(\Magento\Framework\App\Route\ConfigInterface::class);
            $modules = $routeConfig->getModulesByFrontName($frontName);

            return empty($modules) ? '' : $modules[0];
        }
    }

    final class AuditFailedException extends \Exception
    {
        public const TYPE_MODULE = 0x0;
        public const TYPE_ROUTE = 0x1;

        /**
         * @var Entry
         */
        private $entry;

        /**
         * @var int
         */
        private $type;

        public function __construct(Entry $entry, int $type, $message = "", $code = 0, Throwable $previous = null)
        {
            $this->entry = $entry;
            $this->type = $type;
            parent::__construct($message, $code, $previous);
        }

        /**
         * @return Entry
         */
        public function getEntry(): Entry
        {
            return $this->entry;
        }

        /**
         * @return int
         */
        public function getType(): int
        {
            return $this->type;
        }
    }
}

namespace {
    // Setup required args.
    use LamiaOy\Magento2\Blacklist\AuditFailedException;
    use LamiaOy\Magento2\Blacklist\Parser;
    use LamiaOy\Magento2\Blacklist\Scanner;
    use LamiaOy\Magento2\Blacklist\Version;
    use Magento\Framework\Component\ComponentRegistrar;
    use Magento\Framework\Module\ModuleListInterface;

    $useJson = isset($argv[1]);
    $cwd = getcwd();
    $DS = DIRECTORY_SEPARATOR;
    $cwd_ds = "${cwd}${DS}";
    $problems = [];

    // Check if Magento exists, Otherwise die.
    if (!is_dir("${cwd_ds}app")) {
        echo "Current working directory doesnt contain Magento 2.";
        die(1);
    }

    // Initialize Magento Itself.
    require_once "${cwd_ds}app${DS}/bootstrap.php";
    $autoloader = Magento\Framework\Autoload\AutoloaderRegistry::getAutoloader();

    // Fake Magento SERVER params.
    $params = $_SERVER;
    $params[\Magento\Store\Model\StoreManager::PARAM_RUN_CODE] = 'admin';
    $params[\Magento\Store\Model\Store::CUSTOM_ENTRY_POINT_PARAM] = true;
    $params['entryPoint'] = basename(__FILE__);
    $bootstrap = \Magento\Framework\App\Bootstrap::create(BP, $params);

    /** @var LamiaOy\Magento2\Framework\Application $app */
    $app = $bootstrap->createApplication(LamiaOy\Magento2\Framework\Application::class, []);
    $app->launch();

    // Build required services.
    $om = \Magento\Framework\App\ObjectManager::getInstance();
    $blacklist = new Scanner(
        new Version(
            $om->get(ModuleListInterface::class),
            $om->get(ComponentRegistrar::class)
        )
    );

    // If not entries found, it means something went wrong.
    // Exit 2 as indication for internal or network error.
    if (!$blacklist->hasEntries()) {
        echo "Failed to load list of problematic modules.";
        die(2);
    }

     foreach($blacklist->getEntries() as $entry) {
         $scanner = new Parser($entry);
         try {
             $scanner->isVulnerable();
         } catch (AuditFailedException $e) {
             $problems[] = $e;
         }
     }

     if ($problems === []) {
         if ($useJson) {
             file_put_contents("{$cwd_ds}audit.json", '[]');
             die(0);
         }

         echo 'No security issues found!';
         die(0);
     }

     if ($useJson) {
         $data = [];
         /** @var AuditFailedException $problem */
         foreach ($problems as $problem) {
             $data[] = [
                 'current' => $problem->getEntry()->getCurrentVersion(),
                 'module' => $problem->getEntry()->getModuleName(),
                 'reference' => $problem->getEntry()->getCredit(),
                 'update' => $problem->getEntry()->getUpdateUrl(),
                 'fixed_in' => $problem->getEntry()->getFixedIn(),
             ];
         }
         file_put_contents("{$cwd_ds}audit.json", json_encode($data));
     }
}
