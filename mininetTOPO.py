# Topologia di rete implementata:
#
# h1 ---\          /--- hs1
#        \        /
# h2 --- s1 --- s2lb --- hs2
#        /        \
# h3 ---/          \--- hs3
#
# Gli host h1,h2,h3 generano traffico verso gli host hs1,hs2,hs3 usati come server. Lo switch s1 serve solo per
# incanalare il traffico in ingresso allo switch slb che effettuerà il load balance tra i server.


from mininet.topo import Topo


class LBNet(Topo):

    def __init__(self):
        Topo.__init__(self)

        # host client sulla rete 10.0.0.0/24
        host1 = self.addHost('h1', ip = '10.0.0.1/16')
        host2 = self.addHost('h2', ip = '10.0.0.2/16')
        host3 = self.addHost('h3', ip = '10.0.0.3/16')

        # switch
        hostswitch = self.addSwitch('s1')
        loadbalancer = self.addSwitch('s2lb')

        # host server sulla rete 10.0.1.0/24
        # indirizzo di gruppo 4.3.2.1/24
        server1 = self.addHost('hs1', ip = '10.0.1.1/16')
        server2 = self.addHost('hs2', ip = '10.0.1.2/16')
        server3 = self.addHost('hs3', ip = '10.0.1.3/16')

        # collegamenti tra gli elementi della rete secondo la topologia
        self.addLink(host1, hostswitch)
        self.addLink(host2, hostswitch)
        self.addLink(host3, hostswitch)
        self.addLink(hostswitch, loadbalancer)
        self.addLink(loadbalancer, server1)
        self.addLink(loadbalancer, server2)
        self.addLink(loadbalancer, server3)


topos = {'LBNet': (lambda: LBNet())}
