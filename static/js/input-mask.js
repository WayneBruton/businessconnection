/**
 * Phone number input mask
 * Format: (###) ###-####
 */
document.addEventListener('DOMContentLoaded', function() {
    // Get all phone input fields
    const phoneInputs = document.querySelectorAll('.phone-input');
    
    // Apply mask to each phone input
    phoneInputs.forEach(function(input) {
        input.addEventListener('input', function(e) {
            // Get input value and remove all non-digits
            let value = e.target.value.replace(/\D/g, '');
            
            // Limit to 10 digits
            if (value.length > 10) {
                value = value.slice(0, 10);
            }
            
            // Format the number as (###) ###-####
            if (value.length > 0) {
                if (value.length <= 3) {
                    value = '(' + value;
                } else if (value.length <= 6) {
                    value = '(' + value.slice(0, 3) + ') ' + value.slice(3);
                } else {
                    value = '(' + value.slice(0, 3) + ') ' + value.slice(3, 6) + '-' + value.slice(6);
                }
            }
            
            // Update the input value
            e.target.value = value;
        });
        
        // Handle backspace and delete
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' || e.key === 'Delete') {
                // Allow normal behavior for backspace and delete
                return;
            }
            
            // Prevent non-digit input (except for navigation keys)
            if (!/^\d$/.test(e.key) && 
                e.key !== 'ArrowLeft' && 
                e.key !== 'ArrowRight' && 
                e.key !== 'Tab' && 
                !e.ctrlKey && 
                !e.metaKey) {
                e.preventDefault();
            }
        });
    });
});
