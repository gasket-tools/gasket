import os

class Base():
    # @classmethod
    # def from_dict(cls, dict_repr):
    #     return cls(**dict_repr)
    @classmethod
    def from_dict(cls, dict_repr):
        class_name = dict_repr.pop('__class__', None)
        if class_name is None:
            raise ValueError("Dictionary does not contain class information.")

        # Lookup the class in the registry
        target_class = class_registry.get(class_name)
        if target_class is None:
            raise ValueError(f"Unknown class: {class_name}")

        # Create and return an instance of the correct class
        return target_class(**dict_repr)

    def to_dict(self):
        return self.__dict__

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return vars(self) == vars(other)
        return False

class PyCHop(Base):
    def __init__(self, pyname, address, cfunc, section, library):
        self.pyname = pyname
        self.address = int(address)
        self.cfunc = cfunc
        self.section = section
        self.library = library

    def to_dict(self):
        return {"pyname": self.pyname, "cfunc": self.cfunc, "library": self.library}

class PyCBridge(Base):
    def __init__(self, pyname, cfunc, library):
        self.pyname = pyname
        self.cfunc = cfunc
        self.library = library

    def to_dict(self):
        return {
                "pyname": self.pyname, "cfunc": self.cfunc,
                "library": self.library
                }

