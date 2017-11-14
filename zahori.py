from controller import ZahoriController
import view
import model

VNUMBER = '0.1'
print('Zahori %s started' % VNUMBER)

main_view = view.MainView()
model = model.DefaultModel()
ctrl = ZahoriController(model, main_view)

view.start()
