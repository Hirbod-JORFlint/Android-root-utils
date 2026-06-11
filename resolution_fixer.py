import math

def calculate_new_dpi(w1, h1, dpi1, w2, h2):
    """Calculates the new DPI to maintain the same physical UI size."""
    diag1 = math.hypot(w1, h1)
    diag2 = math.hypot(w2, h2)
    new_dpi = dpi1 * (diag2 / diag1)
    return round(new_dpi)

def suggest_resolutions(w1, h1, dpi1):
    """Generates higher and lower resolutions maintaining the aspect ratio."""
    print("\n--- Proportional Resolution Suggestions ---")
    print("Since no target was provided, here are options that maintain your aspect ratio:")
    print(f"{'Scale':<12} | {'Resolution':<12} | {'Recommended DPI':<15}")
    print("-" * 45)
    
    # Common scaling factors for Android modding
    scales = [0.5, 0.75, 1.25, 1.5, 2.0]
    
    for scale in scales:
        w2 = round(w1 * scale)
        h2 = round(h1 * scale)
        new_dpi = calculate_new_dpi(w1, h1, dpi1, w2, h2)
        
        label = "Lower" if scale < 1.0 else "Higher"
        print(f"{label} ({scale}x) | {w2}x{h2:<10} | {new_dpi}")

def main():
    print("--- Android Resolution & DPI Calculator ---")
    try:
        # Get initial specs
        init_res = input("Enter initial resolution (e.g., 480x800): ").lower().strip()
        w1, h1 = map(int, init_res.split('x'))
        
        dpi1 = int(input("Enter initial DPI (e.g., 160): ").strip())
        
        # Get target specs or trigger suggestions
        out_res = input("Enter target resolution (e.g., 720x1200) OR press Enter to see suggestions: ").lower().strip()
        
        if out_res:
            w2, h2 = map(int, out_res.split('x'))
            new_dpi = calculate_new_dpi(w1, h1, dpi1, w2, h2)
            print(f"\n> For a resolution of {w2}x{h2}, your recommended DPI is: {new_dpi}")
        else:
            suggest_resolutions(w1, h1, dpi1)
            
    except ValueError:
        print("\nError: Invalid input. Please use the format 'WidthxHeight' (e.g., 480x800) and integers for DPI.")

if __name__ == "__main__":
    main()
