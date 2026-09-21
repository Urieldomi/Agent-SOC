import unittest

from app import app


class DemoFlowTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_steps_are_sequential_and_report_is_gated(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(self.client.post('/api/run/2').status_code, 409)
        self.assertEqual(self.client.get('/report.pdf').status_code, 409)
        for number in (1, 2, 3):
            response = self.client.post(f'/api/run/{number}')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['step'], number)
        pdf = self.client.get('/report.pdf')
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b'%PDF'))

    def test_scenarios_reset_and_repeat_with_fixed_data(self):
        self.client.post('/api/run/1')
        selected = self.client.post('/api/scenario', json={'scenario': 'safe'})
        self.assertEqual(selected.json['step'], 0)
        self.assertEqual(selected.json['host']['decision'], 'Negativo simulado')
        first = self.client.post('/api/run/1').json['stages'][0]
        self.client.post('/api/reset')
        second = self.client.post('/api/run/1').json['stages'][0]
        self.assertEqual(first, second)
        self.assertEqual(self.client.post('/api/scenario', json={'scenario': 'invalid'}).status_code, 400)

    def test_page_flow_keeps_each_agent_on_its_own_screen(self):
        self.assertEqual(self.client.get('/etapa/3').location, '/etapa/1')
        self.assertEqual(self.client.post('/seleccionar', data={'scenario': 'safe'}).location, '/etapa/1')
        inspection = self.client.get('/etapa/1').get_data(as_text=True)
        self.assertIn('Ejecutar agente de inspección', inspection)
        self.assertNotIn('Registro del agente', inspection)
        self.client.post('/etapa/1/ejecutar')
        inspection = self.client.get('/etapa/1').get_data(as_text=True)
        self.assertIn('Registro del agente', inspection)
        self.assertIn('Continuar a contexto', inspection)
        self.assertNotIn('Fuentes vinculadas al caso', inspection)
        self.assertEqual(self.client.get('/etapa/3').location, '/etapa/2')
        self.client.post('/etapa/2/ejecutar')
        context = self.client.get('/etapa/2').get_data(as_text=True)
        self.assertIn('Fuentes vinculadas al caso', context)
        self.assertIn('Continuar a reporte', context)
        self.client.post('/etapa/3/ejecutar')
        report = self.client.get('/etapa/3').get_data(as_text=True)
        self.assertIn('Descargar reporte PDF', report)
        self.assertNotIn('Fuentes vinculadas al caso', report)


if __name__ == '__main__':
    unittest.main()
