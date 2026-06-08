"""Debug and visualization helpers for the orchestrator."""

import os
import logging

logger = logging.getLogger(__name__)


def save_graph_image(graph, base_dir: str = None) -> None:
    """
    Save the LangGraph structure as a PNG image.

    Args:
        graph: The compiled LangGraph instance
        base_dir: Base directory for saving the image. If None, uses the directory
                  containing this file's parent (orchestrator_helpers/../)
    """
    try:
        if base_dir is None:
            # Default to parent directory of orchestrator_helpers
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        image_path = os.path.join(base_dir, "graph_structure.png")
        png_data = graph.get_graph().draw_mermaid_png()

        with open(image_path, "wb") as f:
            f.write(png_data)

        logger.info(f"Graph structure image saved to {image_path}")
    except Exception as e:
        logger.warning(f"Could not save graph image: {type(e).__name__}: {e}")
