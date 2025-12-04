"""
Visual Comparator
Compares screenshots for visual regression testing.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from PIL import Image, ImageChops, ImageDraw, ImageFilter

logger = logging.getLogger(__name__)


@dataclass
class ComparisonResult:
    """
    Result of visual comparison.

    Attributes:
        match: True if images match within threshold
        difference_percentage: Percentage of different pixels (0-100)
        pixel_differences: Number of different pixels
        total_pixels: Total number of pixels
        diff_image_path: Path to difference visualization (if generated)
    """

    match: bool
    difference_percentage: float
    pixel_differences: int
    total_pixels: int
    diff_image_path: Optional[Path] = None


class VisualComparator:
    """
    Compares screenshots for visual regression testing.

    Features:
    - Pixel-by-pixel comparison
    - Configurable difference threshold
    - Difference visualization
    - Ignore regions support
    - Size mismatch handling
    """

    def __init__(
        self,
        threshold: float = 0.1,
        ignore_antialiasing: bool = True,
        generate_diff_image: bool = True,
    ):
        """
        Initialize visual comparator.

        Args:
            threshold: Acceptable difference percentage (0-100)
            ignore_antialiasing: Reduce false positives from antialiasing
            generate_diff_image: Generate visual diff highlighting changes
        """
        self.threshold = threshold
        self.ignore_antialiasing = ignore_antialiasing
        self.generate_diff_image = generate_diff_image

    def compare_images(
        self,
        baseline_path: Path,
        current_path: Path,
        diff_output_path: Optional[Path] = None,
        ignore_regions: Optional[list[Tuple[int, int, int, int]]] = None,
    ) -> ComparisonResult:
        """
        Compare two images for visual regression.

        Args:
            baseline_path: Path to baseline (expected) image
            current_path: Path to current (actual) image
            diff_output_path: Where to save diff image (optional)
            ignore_regions: List of (x, y, width, height) regions to ignore

        Returns:
            ComparisonResult with comparison details

        Raises:
            FileNotFoundError: If images don't exist
            ValueError: If images have different sizes
        """
        if not baseline_path.exists():
            raise FileNotFoundError(
                f"Baseline image not found: {baseline_path}"
            )

        if not current_path.exists():
            raise FileNotFoundError(f"Current image not found: {current_path}")

        # Load images
        baseline_img = Image.open(baseline_path).convert("RGB")
        current_img = Image.open(current_path).convert("RGB")

        # Check size match
        if baseline_img.size != current_img.size:
            logger.warning(
                f"Size mismatch: baseline={baseline_img.size}, "
                f"current={current_img.size}"
            )
            raise ValueError(
                f"Image size mismatch: {baseline_img.size} vs {current_img.size}"
            )

        # Apply ignore regions
        if ignore_regions:
            baseline_img = self._mask_regions(baseline_img, ignore_regions)
            current_img = self._mask_regions(current_img, ignore_regions)

        # Apply antialiasing filter if enabled
        if self.ignore_antialiasing:
            baseline_img = baseline_img.filter(ImageFilter.SMOOTH_MORE)
            current_img = current_img.filter(ImageFilter.SMOOTH_MORE)

        # Calculate difference
        diff = ImageChops.difference(baseline_img, current_img)

        # Count different pixels
        pixel_differences = sum(
            1 for pixel in diff.getdata() if pixel != (0, 0, 0)
        )

        total_pixels = baseline_img.size[0] * baseline_img.size[1]
        difference_percentage = (pixel_differences / total_pixels) * 100

        # Generate diff visualization
        diff_image_path = None
        if self.generate_diff_image and pixel_differences > 0:
            if diff_output_path is None:
                diff_output_path = (
                    current_path.parent / f"{current_path.stem}_diff.png"
                )

            diff_visualization = self._create_diff_visualization(
                baseline_img, current_img, diff
            )
            diff_visualization.save(diff_output_path)
            diff_image_path = diff_output_path
            logger.debug(f"Diff image saved: {diff_output_path}")

        # Determine match
        match = difference_percentage <= self.threshold

        result = ComparisonResult(
            match=match,
            difference_percentage=difference_percentage,
            pixel_differences=pixel_differences,
            total_pixels=total_pixels,
            diff_image_path=diff_image_path,
        )

        if match:
            logger.info(
                f"✓ Images match ({difference_percentage:.2f}% difference, "
                f"threshold={self.threshold}%)"
            )
        else:
            logger.warning(
                f"✗ Images differ ({difference_percentage:.2f}% difference, "
                f"threshold={self.threshold}%)"
            )

        return result

    def _mask_regions(
        self, image: Image.Image, regions: list[Tuple[int, int, int, int]]
    ) -> Image.Image:
        """
        Mask specified regions in image.

        Args:
            image: Image to mask
            regions: List of (x, y, width, height) regions

        Returns:
            Image with masked regions
        """
        masked = image.copy()
        draw = ImageDraw.Draw(masked)

        for x, y, width, height in regions:
            # Fill region with neutral gray
            draw.rectangle([x, y, x + width, y + height], fill=(128, 128, 128))

        return masked

    def _create_diff_visualization(
        self, baseline: Image.Image, current: Image.Image, diff: Image.Image
    ) -> Image.Image:
        """
        Create visual diff highlighting differences.

        Args:
            baseline: Baseline image
            current: Current image
            diff: Difference image

        Returns:
            Visualization showing differences in red
        """
        # Create side-by-side comparison
        width, height = baseline.size
        visualization = Image.new("RGB", (width * 3, height))

        # Place images side by side
        visualization.paste(baseline, (0, 0))
        visualization.paste(current, (width, 0))

        # Create highlighted diff
        highlighted_diff = current.copy()
        diff_data = diff.getdata()

        # Highlight differences in red
        new_data = []
        for i, pixel in enumerate(highlighted_diff.getdata()):
            if diff_data[i] != (0, 0, 0):
                new_data.append((255, 0, 0))  # Red for differences
            else:
                new_data.append(pixel)

        highlighted_diff.putdata(new_data)
        visualization.paste(highlighted_diff, (width * 2, 0))

        return visualization

    def compare_with_tolerance(
        self,
        baseline_path: Path,
        current_path: Path,
        tolerance: float,
        **kwargs,
    ) -> ComparisonResult:
        """
        Compare images with custom tolerance.

        Args:
            baseline_path: Baseline image path
            current_path: Current image path
            tolerance: Custom tolerance for this comparison
            **kwargs: Additional arguments for compare_images

        Returns:
            ComparisonResult
        """
        original_threshold = self.threshold
        self.threshold = tolerance

        result = self.compare_images(baseline_path, current_path, **kwargs)

        self.threshold = original_threshold
        return result
