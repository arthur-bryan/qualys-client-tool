#!/usr/bin/python3

import sys
from controllers.controller import Controller
from models.menu import Menu
from auxiliary.query_payloads import payloads

controller = Controller()


def main():
	"""Entry point of the program. Use is done through menus."""
	while True:
		main_menu = Menu(controller, "MAIN MENU", ["Get detections from Qualys"])
		choice = main_menu.open()
		if choice == len(main_menu.options):
			sys.exit(0)
		if choice == 1:
			search_type_menu = Menu(controller, "SEARCH MENU", ["Pre-defined queries", "Custom filters"])
			search_type_menu_choice = search_type_menu.open()
			if search_type_menu_choice == len(search_type_menu.options):
				continue
			if search_type_menu_choice == 1:
				query_payload_menu = Menu(controller, "PAYLOADS MENU", list(payloads.keys()))
				query_payload_menu_choice = query_payload_menu.open()
				if query_payload_menu_choice == len(query_payload_menu.options):
					continue
				chosen_payload = query_payload_menu.options[query_payload_menu_choice - 1]
				payload_data = payloads[chosen_payload]
				detections = controller.handle_vm_detections(payload_data)
				detections = controller.filter_period(detections, chosen_payload)
				controller.viewer.show_detections(detections)
				controller.save_data(detections, chosen_payload)
			elif search_type_menu_choice == 2:
				print("CUSTOM FILTERS")
		elif choice == 2:
			continue
		else:
			print("[ - ] Invalid choice!\n")
			continue


if __name__ == "__main__":
	main()
