/**
 * UI Theme Loader
 * Dynamically applies colors and layout parameters from theme.json to CSS variables.
 */
async function loadTheme(configPath = './res/css/theme.json') {
    try {
        const response = await fetch(`${configPath}?v=${Date.now()}`);
        if (!response.ok) throw new Error(`Failed to load theme config (${response.status})`);
        
        const theme = await response.json();
        const root = document.documentElement;

        // Map theme colors to CSS custom variables
        if (theme.colors) {
            Object.entries(theme.colors).forEach(([key, value]) => {
                // Converts camelCase (bgPrimary) to kebab-case (--bg-primary)
                const cssVar = '--' + key.replace(/([a-z0-9]|(?=[A-Z]))([A-Z])/g, '$1-$2').toLowerCase();
                root.style.setProperty(cssVar, value);
            });
        }

        // Map layout variables
        if (theme.layout) {
            Object.entries(theme.layout).forEach(([key, value]) => {
                const cssVar = '--' + key.replace(/([a-z0-9]|(?=[A-Z]))([A-Z])/g, '$1-$2').toLowerCase();
                root.style.setProperty(cssVar, value);
            });
        }

        // Save theme object globally for Chart.js and UI components
        window.APP_THEME = theme;
        
        // Dispatch custom event if other modules need to re-render after theme load
        window.dispatchEvent(new CustomEvent('themeLoaded', { detail: theme }));
    } catch (err) {
        console.warn("Theme loading failed, falling back to CSS defaults:", err);
    }
}

// Automatically load theme on DOM ready
document.addEventListener('DOMContentLoaded', () => loadTheme());