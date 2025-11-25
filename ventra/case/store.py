import os
import re


def get_output_base_dir():
    """Get the base output directory for cases."""
    return os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")


def sanitize_case_name(name):
    """Convert case name to a safe directory name."""
    # Replace spaces and special chars with hyphens, lowercase
    sanitized = re.sub(r'[^\w\s-]', '', name)
    sanitized = re.sub(r'[-\s]+', '-', sanitized)
    return sanitized.lower().strip('-')


def _find_available_case_name(base_name, output_dir):
    """
    Find an available case directory name, handling duplicates.
    Returns the final directory name (e.g., 'ec2-compromise' or 'ec2-compromise-2')
    """
    if not os.path.exists(output_dir):
        return base_name
    
    # Check if base name exists
    base_path = os.path.join(output_dir, base_name)
    if not os.path.exists(base_path) or not os.path.isdir(base_path):
        return base_name
    
    # Find duplicates and get the next number
    counter = 2
    while True:
        candidate = f"{base_name}-{counter}"
        candidate_path = os.path.join(output_dir, candidate)
        if not os.path.exists(candidate_path) or not os.path.isdir(candidate_path):
            return candidate
        counter += 1


def create_case(name):
    """
    Create a new case directory using just the case name.
    Returns: (case_name, case_dir_path)
    """
    output_dir = get_output_base_dir()
    os.makedirs(output_dir, exist_ok=True)
    
    sanitized_name = sanitize_case_name(name)
    case_dir_name = _find_available_case_name(sanitized_name, output_dir)
    case_dir_path = os.path.join(output_dir, case_dir_name)
    
    os.makedirs(case_dir_path, exist_ok=True)
    
    return case_dir_name, case_dir_path


def get_case_dir(case_identifier):
    """
    Find the case directory by name or partial match.
    case_identifier can be:
    - Full directory name (e.g., 'ec2-compromise')
    - Partial match (e.g., 'ec2' will match 'ec2-compromise')
    Returns: case_dir_path or None if not found
    """
    output_dir = get_output_base_dir()
    if not os.path.exists(output_dir):
        return None
    
    # Normalize the identifier
    identifier = sanitize_case_name(case_identifier)
    
    # First try exact match
    exact_path = os.path.join(output_dir, identifier)
    if os.path.exists(exact_path) and os.path.isdir(exact_path):
        return exact_path
    
    # Try partial match - find directories that start with the identifier
    for item in os.listdir(output_dir):
        item_path = os.path.join(output_dir, item)
        if os.path.isdir(item_path):
            # Check if item starts with identifier (with hyphen separator)
            if item == identifier or item.startswith(identifier + '-'):
                return item_path
            # Also check if identifier matches the start of item (for partial matches)
            if item.startswith(identifier):
                return item_path
    
    return None


def list_cases():
    """
    List all cases by scanning the output directory.
    Returns: list of dicts with 'name', 'path'
    """
    output_dir = get_output_base_dir()
    if not os.path.exists(output_dir):
        return []
    
    cases = []
    for item in os.listdir(output_dir):
        item_path = os.path.join(output_dir, item)
        if os.path.isdir(item_path):
            # Convert directory name back to readable name
            case_name = item.replace('-', ' ').title()
            cases.append({
                'name': case_name,
                'dir_name': item,
                'path': item_path
            })
    
    # Sort alphabetically by directory name
    cases.sort(key=lambda x: x['dir_name'])
    return cases


def get_or_create_case(case_identifier=None, auto_name_prefix="Auto Case"):
    """
    Get existing case directory or create a new one.
    If case_identifier is None, auto-create a case.
    case_identifier can be a case name (will be sanitized) or None.
    Returns: (case_name, case_dir_path)
    """
    if case_identifier:
        case_dir = get_case_dir(case_identifier)
        if case_dir:
            # Extract the case name from the directory path
            case_name = os.path.basename(case_dir)
            return case_name, case_dir
        
        # Case not found, create it with the provided name
        return create_case(case_identifier)
    
    # Auto-create case
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    auto_name = f"{auto_name_prefix} - {timestamp}"
    return create_case(auto_name)
