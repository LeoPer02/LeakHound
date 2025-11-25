from . import utilities
from .leak import Leak
from .permission_mapping import get_permissions
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)


def parse_xml(file_path):
    xml_data = utilities.retrieve_xml(file_path)
    if xml_data is None:
        logger.error("Failed to retrieve XML data from the file.")
        raise FileNotFoundError("XML data could not be retrieved.")

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        raise ValueError(e)

    leaks = []  # List to hold multiple Leak objects

    # declared_permissions = []
    #
    # # Find the <DeclaredPermissions> element
    # permissions_declared = root.findall('.//DeclaredPermissions')
    #
    # if permissions_declared:
    #     for permissions in permissions_declared:
    #         # Find all <permission> elements under <PermissionsDeclared>
    #         for permission in permissions.findall('permission'):
    #             declared_permissions.append(permission.text)  # Get the text inside <permission> tag

    # logger.info(f"Declared permissions: {declared_permissions}")
    result_elements = root.findall('./Results/Result')
    if result_elements:
        logger.info(f"Found {len(result_elements)} result(s).")
    else:
        logger.warning("No Result elements found.")
        return None

    for result_element in result_elements:
        leak = Leak()

        # Find the sink for each Result
        sink_element = result_element.find('./Sink')
        if sink_element is not None:
            logger.info("Found Sink element.")
            sink = sink_element.attrib.get('MethodSourceSinkDefinition', '')
        else:
            logger.warning("Sink element is missing.")
            return

        # Add Sink to Leak
        leak.add_sink(sink)

        # Find the sources for each Result
        sources = result_element.findall('./Sources/Source')
        if sources:
            logger.info(f"Found {len(sources)} source(s).")
        else:
            logger.warning("No Source elements found.")

        for source_element in sources:
            source=source_element.attrib.get('MethodSourceSinkDefinition', None)
            if source is None:
                logger.error("Source not found, exiting...")
                raise ValueError("Source not Found")

            # Adding source to the leak's path
            current_path = [source]
            leak.add_data_type(source, get_permissions(source))
            #print("Got source data type")
            taint_path_element = source_element.find('./TaintPath')
            if taint_path_element is not None:
                path_elements = taint_path_element.findall('./PathElement')
                for path_element in path_elements:
                    method_signature = path_element.attrib.get('Method', '')
                    current_path.append(method_signature)  # Collecting the method signature for the path

            # Append the sink method signature to the current path
            # Also add the data type of the sink to the dataTypes structure
            if leak.sink:
                current_path.append(leak.sink)
                leak.add_data_type(leak.sink, get_permissions(leak.sink))

            # Add the populated path to the leak's paths
            leak.paths.append(current_path)

        # Add the populated leak to the list of leaks
        leaks.append(leak)

    logger.info("Parsing complete. Leak objects populated.")
    return leaks  # Return a list of Leak objects
