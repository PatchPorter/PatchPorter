#!/usr/bin/env python3
"""
Plot JavaScript vs C Similarity CDF Comparison
Generates function-level comparison charts (optimized version)
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib import font_manager
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import MultipleLocator, AutoMinorLocator
from pathlib import Path
from scipy.interpolate import interp1d
from scipy.stats import ks_2samp, mannwhitneyu

# Set matplotlib style
plt.style.use('default')
plt.style.use('seaborn-v0_8-paper')

# Global font scale factor (increase to 1.25~1.45 if needed)
FONT_SCALE = 1.25

# Local enhancement: axis ticks & metric title for each subplot
AXIS_TICK_SCALE = 1.15
METRIC_LABEL_SCALE = 1.20


def configure_fonts():
    """Configure fonts with academic-style preferences."""
    system_fonts = {f.name for f in font_manager.fontManager.ttflist}

    # Preferred serif fonts for academic papers; availability varies by system.
    # Common on Linux: TeX Gyre / Libertinus / Nimbus / Liberation / DejaVu
    preferred_serif = [
        'STIX Two Text',
        'STIXGeneral',
        'TeX Gyre Termes',
        'TeX Gyre Pagella',
        'Libertinus Serif',
        'Nimbus Roman',
        'Times New Roman',
        'Liberation Serif',
        'DejaVu Serif',
        'serif',
    ]

    available_serif = [name for name in preferred_serif if (name in system_fonts) or (name == 'serif')]

    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = available_serif


configure_fonts()

# Academic typesetting: unified rcParams (LaTeX not required)
mpl.rcParams.update({
    'font.weight': 'regular',
    'axes.labelweight': 'regular',
    'axes.titleweight': 'regular',
    'mathtext.fontset': 'stix',
    'mathtext.default': 'regular',
    'axes.unicode_minus': False,

    # PDF/PS font embedding
    'pdf.fonttype': 42,
    'ps.fonttype': 42,

    # Global font sizes (with FONT_SCALE applied)
    'font.size': 11 * FONT_SCALE,
    'axes.labelsize': 12 * FONT_SCALE,
    'axes.titlesize': 13 * FONT_SCALE,
    'xtick.labelsize': 11 * FONT_SCALE,
    'ytick.labelsize': 11 * FONT_SCALE,
    'legend.fontsize': 12 * FONT_SCALE,

    # Academic-style lines and borders
    'axes.linewidth': 0.8,
    'lines.linewidth': 2.0,
    'lines.solid_capstyle': 'round',

    # Ticks: inward direction + minor ticks
    'xtick.direction': 'in',
    'ytick.direction': 'in',
    'xtick.major.size': 5.5,
    'ytick.major.size': 5.5,
    'xtick.minor.size': 3.5,
    'ytick.minor.size': 3.5,
    'xtick.major.width': 0.8,
    'ytick.major.width': 0.8,
    'xtick.minor.width': 0.6,
    'ytick.minor.width': 0.6,

    # Export settings
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
})

# Result file paths
RESULTS_DIR = Path('similarity_results')

# JavaScript data (new format: list)
JS_FUNCTION_SIMILARITY = RESULTS_DIR / 'js-function_similarity.json'

# JavaScript Commit data (new format: CVE dictionary)
JS_COMMIT_FUNCTION = RESULTS_DIR / 'js-commit_function.json'

# C language data (new format: list, same as JavaScript format)
C_FUNCTION_SIMILARITY = RESULTS_DIR / 'c-function_similarity.json'

# Embedding similarity data (newly computed results)
JS_EMBEDDING_FUNCTION = RESULTS_DIR / 'function_embedding_results' / 'js-function-embedding.json'
C_EMBEDDING_FUNCTION = RESULTS_DIR / 'function_embedding_results' / 'c-function-embedding.json'
JS_COMMIT_EMBEDDING_FUNCTION = RESULTS_DIR / 'function_embedding_results' / 'js-commit-function-embedding.json'

# Output directory
OUTPUT_DIR = Path('similarity_figures')
OUTPUT_DIR.mkdir(exist_ok=True)


def load_js_similarity_data(file_path):
    """Load JavaScript similarity data (new format: direct list)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_c_similarity_data(file_path):
    """Load C language similarity data (new format: direct list, same as JavaScript)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_js_metrics(data):
    """Extract metrics from JavaScript data (pair-wise, each item independent)."""
    metrics = {
        'jaccard': [],
        'line_diff': [],
        'bleu': [],
        'best_match_statement': [],
        'best_match_line_context': [],
    }
    
    for item in data:
        if isinstance(item, dict):
            for metric in metrics.keys():
                value = item.get(metric, -1)
                if value != -1 and value not in (0.0, 1.0):  # Exclude 0 and 1
                    metrics[metric].append(value)
    
    return metrics


def extract_embedding_metrics(data):
    """
    Extract embedding_similarity metric from Embedding data (dictionary format, key is item_id).
    
    Note: -1 indicates failed computation; keep values in [0,1] excluding extreme cases
    """
    embedding_values = []
    
    for item_id, item_data in data.items():
        if isinstance(item_data, dict) and 'embedding_similarity' in item_data:
            value = item_data['embedding_similarity']
            
            # Only exclude -1 (failed computation) and exact 0 or 1
            if value != -1 and value not in (0.0, 1.0):
                embedding_values.append(value)
    
    return embedding_values


def extract_c_metrics(data):
    """Extract metrics from C language data (pair-wise, each item independent)."""
    metrics = {
        'jaccard': [],
        'line_diff': [],
        'bleu': [],
        'best_match_statement': [],
        'best_match_line_context': [],
    }
    
    for item in data:
        if isinstance(item, dict):
            for metric in metrics.keys():
                value = item.get(metric, -1)
                if value != -1 and value not in (0.0, 1.0):  # Exclude 0 and 1
                    metrics[metric].append(value)
    
    return metrics


def extract_js_commit_metrics(data):
    """Extract function-level metrics from JS-Commit data (CVE dictionary format)."""
    metrics = {
        'jaccard': [],
        'line_diff': [],
        'bleu': [],
        'best_match_statement': [],
        'best_match_line_context': [],
    }
    
    for cve_id, cve_data in data.items():
        items = cve_data.get('function', [])
        
        for item in items:
            for metric in metrics.keys():
                value = item.get(metric, -1)
                if value != -1 and value not in (0.0, 1.0):  # Exclude 0 and 1
                    metrics[metric].append(value)
    
    return metrics


def plot_smooth_cdf(data, ax, linestyle, color, label):
    """Plot a smooth CDF curve (optimized version)."""
    if not data:
        return
    
    # Sort data
    sorted_data = np.sort(data)
    n = len(sorted_data)
    
    # Calculate cumulative probability
    y = np.arange(1, n + 1) / n
    
    # Use interpolation to increase smoothness if data points < 100
    if n < 100:
        # Create interpolation function (linear interpolation)
        x_smooth = np.linspace(sorted_data[0], sorted_data[-1], 500)
        f = interp1d(sorted_data, y, kind='linear', bounds_error=False, fill_value=(0, 1))
        y_smooth = f(x_smooth)
        if label:
            ax.plot(x_smooth, y_smooth, linestyle=linestyle, linewidth=2.2, 
                   label=label, color=color, alpha=0.85)
        else:
            ax.plot(x_smooth, y_smooth, linestyle=linestyle, linewidth=2.2, 
                   color=color, alpha=0.85)
    else:
        # Enough data points, plot directly
        if label:
            ax.plot(sorted_data, y, linestyle=linestyle, linewidth=2.2, 
                   label=label, color=color, alpha=0.85)
        else:
            ax.plot(sorted_data, y, linestyle=linestyle, linewidth=2.2, 
                   color=color, alpha=0.85)


def draw_comparison_grid(js_metrics, c_metrics, js_commit_metrics, level, output_file):
    """
    Plot JavaScript vs C vs JS-Commit comparison chart (refined version).
    
    Features:
    - Fill effects for visual distinction
    - Mean/median annotations
    - Minor tick grid
    - Sample size annotations and global summary
    - Top legend for language identification
    """
    
    # Local font scaling function
    def fs(size, scale=1.0):
        return float(size) * FONT_SCALE * float(scale)
    
    # All 6 metrics (2x3 layout)
    all_metrics = [
        ('jaccard', 'Token Jaccard Similarity'),
        ('line_diff', 'Line Jaccard Similarity'),
        ('bleu', 'BLEU'),
        ('embedding_similarity', 'Embedding Similarity'),
        ('best_match_statement', 'Top-1 Statement-Level EDS'),
        ('best_match_line_context', 'Top-1 Context-Level EDS'),
    ]
    
    # Define line styles and colors (optimized color scheme)
    styles = {
        'js': {'linestyle': '--', 'color': '#2E86AB', 'linewidth': 2.0, 'label': 'JavaScript'},
        'c': {'linestyle': '-', 'color': '#E63946', 'linewidth': 2.0, 'label': 'C'},
        'commit': {'linestyle': '-.', 'color': '#06A77D', 'linewidth': 2.0, 'label': 'JS-Commit'}
    }
    
    # Create 2x3 subplot layout (optimized size ratio)
    fig, axes = plt.subplots(2, 3, figsize=(12.5, 6), 
                            sharex=False, sharey=False)
    axes = axes.flatten()
    
    for idx, (metric_name, metric_label) in enumerate(all_metrics):
        ax = axes[idx]
        
        js_data = js_metrics.get(metric_name, [])
        c_data = c_metrics.get(metric_name, [])
        js_commit_data = js_commit_metrics.get(metric_name, [])
        
        # Decide whether to plot commit data (Best Match metrics excluded)
        # First 4 metrics include commit data: jaccard, line_diff, bleu, embedding_similarity
        show_commit = idx < 4
        
        # --- Difference highlighting core logic ---
        # Calculate Mann-Whitney U test and fill difference area
        p_text_mw = None
        if js_data and c_data:
            u_stat, p_value = mannwhitneyu(js_data, c_data, alternative='two-sided')
            
            # Format P value (using LaTeX math format)
            if p_value < 0.001:
                p_text_mw = r"MW-Test: $p < 0.001$"
            else:
                p_text_mw = fr"MW-Test: $p = {p_value:.3f}$"
                
            # Create common X-axis grid for interpolation (0 to 1, assuming all similarities in this range)
            x_grid = np.linspace(0, 1, 500)
            
            # Calculate interpolated CDF
            def get_cdf_interp(data, grid):
                sorted_d = np.sort(data)
                y = np.arange(1, len(sorted_d)+1) / len(sorted_d)
                return np.interp(grid, sorted_d, y, left=0, right=1)
                
            js_cdf_interp = get_cdf_interp(js_data, x_grid)
            c_cdf_interp = get_cdf_interp(c_data, x_grid)
            
            # Fill difference area (gray hatching, elegant style)
            ax.fill_between(x_grid, js_cdf_interp, c_cdf_interp, 
                           color='#777777', alpha=0.1, hatch='///', edgecolor='none', zorder=0)

        # Calculate mean/std for annotation
        js_mean = np.mean(js_data) if js_data else 0
        c_mean = np.mean(c_data) if c_data else 0
        js_commit_mean = np.mean(js_commit_data) if (show_commit and js_commit_data) else 0
        
        js_std = np.std(js_data) if js_data else 0
        c_std = np.std(c_data) if c_data else 0
        js_commit_std = np.std(js_commit_data) if (show_commit and js_commit_data) else 0

        # Plot curves and fill
        if js_data:
            plot_smooth_cdf(js_data, ax, styles['js']['linestyle'], 
                          styles['js']['color'], None)
            # Add light fill (interpolated for smoothness)
            sorted_data = np.sort(js_data)
            y = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
            x_smooth = np.linspace(sorted_data[0], sorted_data[-1], 400)
            y_smooth = np.interp(x_smooth, sorted_data, y)
            ax.fill_between(x_smooth, y_smooth, color=styles['js']['color'], alpha=0.08)
            
        if c_data:
            plot_smooth_cdf(c_data, ax, styles['c']['linestyle'], 
                          styles['c']['color'], None)
            sorted_data = np.sort(c_data)
            y = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
            x_smooth = np.linspace(sorted_data[0], sorted_data[-1], 400)
            y_smooth = np.interp(x_smooth, sorted_data, y)
            ax.fill_between(x_smooth, y_smooth, color=styles['c']['color'], alpha=0.08)

        if show_commit and js_commit_data:
            plot_smooth_cdf(js_commit_data, ax, styles['commit']['linestyle'], 
                          styles['commit']['color'], None)
            sorted_data = np.sort(js_commit_data)
            y = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
            x_smooth = np.linspace(sorted_data[0], sorted_data[-1], 400)
            y_smooth = np.interp(x_smooth, sorted_data, y)
            ax.fill_between(x_smooth, y_smooth, color=styles['commit']['color'], alpha=0.08)

        # Add detailed statistics box (upper left, below Metric Title)
        # Content: mean (std)
        start_y = 0.80
        step_y = 0.11
        
        # Descriptive statistics - upper left
        if js_data: 
            text = fr"$\mu={js_mean:.2f}\ (\sigma={js_std:.2f})$"
            ax.text(0.05, start_y, text, transform=ax.transAxes,
                 fontsize=fs(12), va='top', ha='left',
                   color=styles['js']['color'], fontweight='normal',
                   bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.7, edgecolor='none'))
            start_y -= step_y
            
        if c_data: 
            text = fr"$\mu={c_mean:.2f}\ (\sigma={c_std:.2f})$"
            ax.text(0.05, start_y, text, transform=ax.transAxes,
                 fontsize=fs(12), va='top', ha='left',
                   color=styles['c']['color'], fontweight='normal',
                   bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.7, edgecolor='none'))
            start_y -= step_y

        # For first 4 plots (including embedding), MW-Test above Commit data
        if idx < 4 and p_text_mw:
            text = f"{p_text_mw}"
            ax.text(0.05, start_y, text, transform=ax.transAxes,
                 fontsize=fs(12), va='top', ha='left',
                   color='#555555', fontweight='normal',
                   bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.7, edgecolor='none'))
            start_y -= step_y * 1.5

        if show_commit and js_commit_data:
            text = fr"$\mu={js_commit_mean:.2f}\ (\sigma={js_commit_std:.2f})$"
            ax.text(0.05, start_y, text, transform=ax.transAxes,
                 fontsize=fs(12), va='top', ha='left',
                   color=styles['commit']['color'], fontweight='normal',
                   bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.7, edgecolor='none'))
            start_y -= step_y

        # For last 2 plots (Best Match), no commit data, MW-Test at the end
        if idx >= 4 and p_text_mw:
            text = f"{p_text_mw}"
            ax.text(0.05, start_y, text, transform=ax.transAxes,
                 fontsize=fs(12), va='top', ha='left',
                   color='#555555', fontweight='normal',
                   bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.7, edgecolor='none'))
            start_y -= step_y

        # Set subplot properties
        # Metric Label - academic style, smaller font size
        ax.text(0.05, 0.95, metric_label, transform=ax.transAxes,
             fontsize=fs(11, METRIC_LABEL_SCALE), fontweight='normal', va='top', ha='left',
               bbox=dict(boxstyle='round,pad=0.35', facecolor='white', 
                        edgecolor='#999999', alpha=0.95, linewidth=0.7))
        
        # Remove ylabel
        ax.set_ylabel('')
        ax.tick_params(axis='y', labelleft=(idx % 3 == 0))
        
        # Remove x label
        ax.tick_params(axis='x', labelbottom=(idx >= 3))

        # Optimize ticks - add minor ticks
        ax.xaxis.set_major_locator(MultipleLocator(0.25))
        ax.xaxis.set_minor_locator(AutoMinorLocator(2))
        ax.yaxis.set_major_locator(MultipleLocator(0.25))
        ax.yaxis.set_minor_locator(AutoMinorLocator(2))
        
        # Optimize grid style
        ax.grid(True, which='major', alpha=0.3, linestyle='-', linewidth=0.8, color='gray')
        ax.grid(True, which='minor', alpha=0.1, linestyle=':', linewidth=0.5, color='gray')
        ax.set_axisbelow(True)
        
        # Optimize tick style - academic style, moderate font size
        ax.tick_params(which='major', labelsize=fs(11, AXIS_TICK_SCALE), pad=4, length=5, width=0.8)
        ax.tick_params(which='minor', length=3, width=0.5)
        
        # Set axis range (with margins)
        ax.set_xlim(-0.02, 1.02)
        ax.set_ylim(-0.02, 1.02)
        
        # Unified tick label format (0.00->0, 1.00->1)
        standard_ticks = [0, 0.25, 0.5, 0.75, 1.0]
        standard_labels = ['0', '0.25', '0.50', '0.75', '1']
        
        ax.set_xticks(standard_ticks)
        ax.set_xticklabels(standard_labels, fontsize=fs(11, AXIS_TICK_SCALE))
        
        ax.set_yticks(standard_ticks)
        ax.set_yticklabels(standard_labels, fontsize=fs(11, AXIS_TICK_SCALE))
        
        # Add border
        for spine in ax.spines.values():
            spine.set_linewidth(0.8)
            spine.set_color('#333333')
        
        # Special handling: 5th plot (idx=4, Best Match Statement) annotate intersection at x=0.55
        if idx == 4 and js_data and c_data:
            x_mark = 0.55
            
            # Modify x-axis ticks: add 0.55, remove 0.50
            custom_xticks = [0, 0.25, 0.55, 0.75, 1.0]
            custom_xlabels = ['0', '0.25', '0.55', '0.75', '1']
            ax.set_xticks(custom_xticks)
            ax.set_xticklabels(custom_xlabels, fontsize=fs(11, AXIS_TICK_SCALE))
            
            # Set 0.55 to red
            for label, tick in zip(ax.get_xticklabels(), custom_xticks):
                if tick == 0.55:
                    label.set_color('red')
                    label.set_fontweight('bold')
            
            # Calculate CDF value at x=0.55 (linear interpolation)
            # JavaScript
            sorted_js = np.sort(js_data)
            y_js_cdf = np.arange(1, len(sorted_js) + 1) / len(sorted_js)
            y_js_at_mark = np.interp(x_mark, sorted_js, y_js_cdf)
            
            # C
            sorted_c = np.sort(c_data)
            y_c_cdf = np.arange(1, len(sorted_c) + 1) / len(sorted_c)
            y_c_at_mark = np.interp(x_mark, sorted_c, y_c_cdf)
            
            # Draw vertical dashed line (only to blue line intersection)
            ax.plot([x_mark, x_mark], [0, y_js_at_mark], color='#555555', linestyle='--', 
                   linewidth=2.0, alpha=0.8, zorder=5)
            
            # Mark two intersection points (larger markers)
            ax.plot(x_mark, y_js_at_mark, 'o', color=styles['js']['color'], 
                   markersize=10, markeredgewidth=2.5, markeredgecolor='white', zorder=10)
            ax.plot(x_mark, y_c_at_mark, 'o', color=styles['c']['color'], 
                   markersize=10, markeredgewidth=2.5, markeredgecolor='white', zorder=10)
            
            # Add horizontal dashed lines on y-axis (bolder and darker)
            ax.axhline(y=y_js_at_mark, color=styles['js']['color'], linestyle='--', 
                      linewidth=1.8, alpha=0.7, zorder=5)
            ax.axhline(y=y_c_at_mark, color=styles['c']['color'], linestyle='--', 
                      linewidth=1.8, alpha=0.7, zorder=5)
            
            # Add text annotations on left y-axis
            # Adjust positions to avoid overlap
            offset = 0.03
            if abs(y_js_at_mark - y_c_at_mark) < 0.05:  # If two values too close
                y_js_text = y_js_at_mark + offset
                y_c_text = y_c_at_mark - offset
            else:
                y_js_text = y_js_at_mark
                y_c_text = y_c_at_mark
            
            # Add annotations to the right of left axis
            ax.text(0.02, y_js_text, f'{y_js_at_mark:.2f}', 
                     transform=ax.transData, fontsize=fs(10), fontweight='normal',
                   color=styles['js']['color'], ha='left', va='center',
                   bbox=dict(boxstyle='round,pad=0.25', facecolor='white', 
                            edgecolor=styles['js']['color'], alpha=0.95, linewidth=1.0),
                   zorder=20)
            ax.text(0.02, y_c_text, f'{y_c_at_mark:.2f}', 
                     transform=ax.transData, fontsize=fs(10), fontweight='normal',
                   color=styles['c']['color'], ha='left', va='center',
                   bbox=dict(boxstyle='round,pad=0.25', facecolor='white', 
                            edgecolor=styles['c']['color'], alpha=0.95, linewidth=1.0),
                   zorder=20)
    
    # Language legend at the top of the figure
    legend_elements = [
        Line2D([0], [0], color=styles['js']['color'], lw=2.0, linestyle=styles['js']['linestyle'], label='NPM'),
        Line2D([0], [0], color=styles['c']['color'], lw=2.0, linestyle=styles['c']['linestyle'], label='C Ecosystem'),
        Line2D([0], [0], color=styles['commit']['color'], lw=2.0, linestyle=styles['commit']['linestyle'], label='NPM (commit-level split)'),
        Patch(facecolor='none', edgecolor='none', label=r'$\mathbf{EDS}$: Edit Distance Similarity')
    ]
    # Academic-style legend: no border, upper right, single row
    fig.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.98, 0.96), 
              ncol=4, fontsize=fs(13), frameon=False, columnspacing=1.5,
              handlelength=2.5)
    
    # Optimize layout spacing
    plt.subplots_adjust(left=0.04, right=0.99, top=0.88, bottom=0.06, 
                       hspace=0.08, wspace=0.12)
    
    # Save high-quality image
    plt.savefig(output_file, bbox_inches='tight', dpi=300, 
                facecolor='white', edgecolor='none')
    plt.close()
    print(f"  Saved: {output_file}")


def main():
    print("=" * 60)
    print("Plotting JavaScript vs C Similarity CDF Comparison (Function Level)")
    print("=" * 60)
    
    # ===== Function Level =====
    print("\n[Function Level]")
    if JS_FUNCTION_SIMILARITY.exists() and C_FUNCTION_SIMILARITY.exists() and JS_COMMIT_FUNCTION.exists():
        print("  Loading data...")
        js_func_data = load_js_similarity_data(JS_FUNCTION_SIMILARITY)
        c_func_data = load_c_similarity_data(C_FUNCTION_SIMILARITY)
        js_commit_data = load_js_similarity_data(JS_COMMIT_FUNCTION)
        
        print(f"    JavaScript: {len(js_func_data)} items")
        print(f"    C: {len(c_func_data)} items")
        print(f"    JS-Commit: {len(js_commit_data)} CVEs")
        
        print("  Extracting metrics...")
        js_func_metrics = extract_js_metrics(js_func_data)
        c_func_metrics = extract_c_metrics(c_func_data)
        js_commit_metrics = extract_js_commit_metrics(js_commit_data)
        
        # Load and extract embedding similarity data
        print("  Loading embedding data...")
        if JS_EMBEDDING_FUNCTION.exists() and C_EMBEDDING_FUNCTION.exists():
            with open(JS_EMBEDDING_FUNCTION, 'r', encoding='utf-8') as f:
                js_embedding_data = json.load(f)
            with open(C_EMBEDDING_FUNCTION, 'r', encoding='utf-8') as f:
                c_embedding_data = json.load(f)
            
            js_embedding_values = extract_embedding_metrics(js_embedding_data)
            c_embedding_values = extract_embedding_metrics(c_embedding_data)
            
            # Load JS-Commit embedding data
            js_commit_embedding_values = []
            if JS_COMMIT_EMBEDDING_FUNCTION.exists():
                with open(JS_COMMIT_EMBEDDING_FUNCTION, 'r', encoding='utf-8') as f:
                    js_commit_embedding_data = json.load(f)
                js_commit_embedding_values = extract_embedding_metrics(js_commit_embedding_data)
                print(f"    JS-Commit Embedding: {len(js_commit_embedding_values)} points")
            
            # Add embedding data to metrics dictionaries
            js_func_metrics['embedding_similarity'] = js_embedding_values
            c_func_metrics['embedding_similarity'] = c_embedding_values
            js_commit_metrics['embedding_similarity'] = js_commit_embedding_values
            
            print(f"    JavaScript Embedding: {len(js_embedding_values)} points")
            print(f"    C Embedding: {len(c_embedding_values)} points")
        else:
            print("  Warning: Embedding data files not found, using empty data")
            js_func_metrics['embedding_similarity'] = []
            c_func_metrics['embedding_similarity'] = []
            js_commit_metrics['embedding_similarity'] = []
        
        print(f"    JavaScript after filtering: {len(js_func_metrics['jaccard'])} points")
        print(f"    C after filtering: {len(c_func_metrics['jaccard'])} points")
        print(f"    JS-Commit after filtering: {len(js_commit_metrics['jaccard'])} points")
        
        print("\n  Plotting Function Level CDF chart...")
        draw_comparison_grid(js_func_metrics, c_func_metrics, js_commit_metrics, 'Function',
                           OUTPUT_DIR / 'cdf_function_level_js_vs_c.pdf')
    else:
        print(f"  Error: Required data files not found")
        if not JS_FUNCTION_SIMILARITY.exists():
            print(f"    Missing: {JS_FUNCTION_SIMILARITY}")
        if not C_FUNCTION_SIMILARITY.exists():
            print(f"    Missing: {C_FUNCTION_SIMILARITY}")
        if not JS_COMMIT_FUNCTION.exists():
            print(f"    Missing: {JS_COMMIT_FUNCTION}")
    
    print("\n" + "=" * 60)
    print(f"Done! Charts saved to {OUTPUT_DIR}/ directory")
    print("=" * 60)


if __name__ == '__main__':
    main()
