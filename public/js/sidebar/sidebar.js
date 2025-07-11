document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.querySelector('.sidebar');
    const menuToggle = document.querySelector('.menu-toggle');
    const sidebarLinks = document.querySelectorAll('.sidebar ul li a');
    const dashboardSections = document.querySelectorAll('.dashboard-section');

    // Function to show a specific dashboard section
    function showSection(sectionId) {
        dashboardSections.forEach(section => {
            section.classList.remove('active-section');
        });
        const activeSection = document.getElementById(sectionId);
        if (activeSection) {
            activeSection.classList.add('active-section');
        }
    }

    // Function to handle sidebar link clicks
    function handleSidebarLinkClick(event) {
        event.preventDefault(); // Prevent default link behavior
        
        // Remove 'active' class from all links
        sidebarLinks.forEach(link => link.classList.remove('active'));
        
        // Add 'active' class to the clicked link
        event.currentTarget.classList.add('active');

        // Get the data-section attribute and show the corresponding section
        const sectionId = event.currentTarget.dataset.section;
        if (sectionId) {
            showSection(sectionId);
        }

        // Hide sidebar on mobile after a link is clicked
        if (window.innerWidth <= 992) { // Match CSS breakpoint
            sidebar.classList.remove('active');
        }
    }

    // Event listener for sidebar menu toggle (for mobile)
    if (menuToggle) {
        menuToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }

    // Event listeners for each sidebar link
    sidebarLinks.forEach(link => {
        link.addEventListener('click', handleSidebarLinkClick);
    });

    // Optional: Close sidebar if clicked outside on mobile (simplistic)
    document.addEventListener('click', function(event) {
        if (window.innerWidth <= 992 && sidebar.classList.contains('active') && 
            !sidebar.contains(event.target) && !menuToggle.contains(event.target)) {
            sidebar.classList.remove('active');
        }
    });

    // Initialize: Show the dashboard overview section by default
    showSection('dashboard-section');
});