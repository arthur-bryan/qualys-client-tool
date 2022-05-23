class Menu:

    def __init__(self, controller, title, options):
        self.controller = controller
        self.title = title
        self.options = options
        self.invalid_message = "[ - ] Invalid choice!\n"

    def open(self):
        self.controller.viewer.show_menu_options(self.title, self.options)
        while True:
            try:
                choice = int(input("---> "))
            except ValueError:
                print(self.invalid_message)
                continue
            else:
                if choice not in range(1, len(self.options) + 1):
                    print(self.invalid_message)
                    continue
                return choice
