// Remove the import/export syntax and define directly
const ThemeToggle = () => {
	const [isDark, setIsDark] = React.useState(false);

	React.useEffect(() => {
		// Check if user has a saved preference
		const savedTheme = localStorage.getItem('theme');

		// Check system preference
		const prefersDark = window.matchMedia(
			'(prefers-color-scheme: dark)'
		).matches;

		// Set initial theme based on saved preference or system preference
		if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
			setIsDark(true);
			document.documentElement.classList.add('dark-mode');
		}

		// Listen for system preference changes
		const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
		const handleChange = (e) => {
			if (!localStorage.getItem('theme')) {
				// Only auto-switch if user hasn't set a preference
				setIsDark(e.matches);
				document.documentElement.classList.toggle('dark-mode', e.matches);
			}
		};

		mediaQuery.addListener(handleChange);
		return () => mediaQuery.removeListener(handleChange);
	}, []);

	const toggleTheme = () => {
		setIsDark(!isDark);
		document.documentElement.classList.toggle('dark-mode');
		localStorage.setItem('theme', !isDark ? 'dark' : 'light');
	};

	return React.createElement(
		'div',
		{
			style: {
				position: 'fixed',
				bottom: '1rem',
				right: '1rem',
				zIndex: 1000,
			},
		},
		React.createElement(
			'button',
			{
				onClick: toggleTheme,
				style: {
					width: '48px',
					height: '48px',
					borderRadius: '24px',
					backgroundColor: isDark ? '#4B5563' : '#ffffff',
					boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
					border: 'none',
					cursor: 'pointer',
					display: 'flex',
					alignItems: 'center',
					justifyContent: 'center',
					transition: 'all 0.3s ease',
				},
				'aria-label': 'Toggle theme',
			},
			React.createElement(
				'svg',
				{
					width: '24',
					height: '24',
					viewBox: '0 0 24 24',
					fill: 'none',
					stroke: isDark ? '#FCD34D' : '#4B5563',
					strokeWidth: '2',
					strokeLinecap: 'round',
					strokeLinejoin: 'round',
				},
				isDark
					? [
							// Sun icon paths
							React.createElement('circle', {
								key: 'circle',
								cx: '12',
								cy: '12',
								r: '5',
							}),
							React.createElement('line', {
								key: 'line1',
								x1: '12',
								y1: '1',
								x2: '12',
								y2: '3',
							}),
							React.createElement('line', {
								key: 'line2',
								x1: '12',
								y1: '21',
								x2: '12',
								y2: '23',
							}),
							React.createElement('line', {
								key: 'line3',
								x1: '4.22',
								y1: '4.22',
								x2: '5.64',
								y2: '5.64',
							}),
							React.createElement('line', {
								key: 'line4',
								x1: '18.36',
								y1: '18.36',
								x2: '19.78',
								y2: '19.78',
							}),
							React.createElement('line', {
								key: 'line5',
								x1: '1',
								y1: '12',
								x2: '3',
								y2: '12',
							}),
							React.createElement('line', {
								key: 'line6',
								x1: '21',
								y1: '12',
								x2: '23',
								y2: '12',
							}),
							React.createElement('line', {
								key: 'line7',
								x1: '4.22',
								y1: '19.78',
								x2: '5.64',
								y2: '18.36',
							}),
							React.createElement('line', {
								key: 'line8',
								x1: '18.36',
								y1: '5.64',
								x2: '19.78',
								y2: '4.22',
							}),
					  ]
					: [
							// Moon icon paths
							React.createElement('path', {
								key: 'moon',
								d: 'M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z',
							}),
					  ]
			)
		)
	);
};
