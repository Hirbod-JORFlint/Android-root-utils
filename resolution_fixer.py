import math

def calculate_proportional_dpi(w1, h1, dpi1, w2, h2):
    """Calculates the new DPI to maintain the same physical UI size as the original setup."""
    diag1 = math.hypot(w1, h1)
    diag2 = math.hypot(w2, h2)
    new_dpi = dpi1 * (diag2 / diag1)
    return round(new_dpi)

def suggest_ideal_dpi(w2, h2):
    """Calculates true hardware DPI based on physical screen size and suggests standard Android buckets."""
    try:
        inches = float(input("\nWhat is your phone's physical screen size in inches? (e.g., 4.0, 5.5): ").strip())
        diag_pixels = math.hypot(w2, h2)
        true_dpi = round(diag_pixels / inches)
        
        # Standard Android display density buckets
        standard_buckets = [120, 160, 240, 320, 480, 640, 800]
        closest_bucket = min(standard_buckets, key=lambda x: abs(x - true_dpi))
        
        print(f"\n--- Ideal DPI Suggestions for {w2}x{h2} on a {inches}\" display ---")
        print(f"> True Hardware DPI: {true_dpi} (Crispest visually, but some apps may scale weirdly)")
        print(f"> Standard Android DPI: {closest_bucket} (Nearest official bucket, best for app compatibility)")
        print(f"> Recommended Custom: {true_dpi - (true_dpi % 10)} (A clean rounded number close to true hardware)")
        
    except ValueError:
        print("\nError: Please enter a valid number for screen inches (e.g., 5.0).")

def suggest_resolutions(w1, h1, dpi1):
    """Generates higher and lower resolutions maintaining the aspect ratio."""
    print("\n--- Proportional Resolution Suggestions ---")
    print("Since no target was provided, here are options that maintain your aspect ratio:")
    print(f"{'Scale':<12} | {'Resolution':<12} | {'Proportional DPI':<15}")
    print("-" * 45)
    
    scales = [0.5, 0.75, 1.25, 1.5, 2.0]
    
    for scale in scales:
        w2 = round(w1 * scale)
        h2 = round(h1 * scale)
        new_dpi = calculate_proportional_dpi(w1, h1, dpi1, w2, h2)
        
        label = "Lower" if scale < 1.0 else "Higher"
        print(f"{label} ({scale}x) | {w2}x{h2:<10} | {new_dpi}")

def main():
    print("--- Android Resolution & DPI Calculator ---")
    try:
        # Get initial specs
        init_res = input("Enter current resolution (e.g., 480x800): ").lower().strip()
        w1, h1 = map(int, init_res.split('x'))
        
        dpi1 = int(input("Enter current DPI (e.g., 160): ").strip())
        
        # Get target specs
        out_res = input("\nEnter target resolution (e.g., 720x1200) OR press Enter to see suggestions: ").lower().strip()
        
        if out_res:
            w2, h2 = map(int, out_res.split('x'))
            
            print("\nHow would you like to calculate the DPI for this new resolution?")
            print("1. Proportional (Keep UI elements the exact same size as they are now)")
            print("2. Ideal/Hardware (Calculate the true, optimal DPI from scratch based on screen inches)")
            
            choice = input("Enter 1 or 2: ").strip()
            
            if choice == '1':
                new_dpi = calculate_proportional_dpi(w1, h1, dpi1, w2, h2)
                print(f"\n> To keep your UI looking exactly the same at {w2}x{h2}, use DPI: {new_dpi}")
            elif choice == '2':
                suggest_ideal_dpi(w2, h2)
            else:
                print("\nInvalid choice. Please run the script again and select 1 or 2.")
                
        else:
            suggest_resolutions(w1, h1, dpi1)
            
    except ValueError:
        print("\nError: Invalid input. Please use the format 'WidthxHeight' (e.g., 480x800) and standard numbers.")

if __name__ == "__main__":
    main()
