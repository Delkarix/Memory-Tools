   M S B A M L   `   `   `  ����G  CMemory Tools, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null+clr-namespace:Memory_ToolsMemory_Tools  5   	   A%clr-namespace:Memory_Tools.PropertiesMemory_Tools.Properties  5   	   "    Memory_Tools.ProcessSelector   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   +selfclr-namespace:Memory_Tools     5   	   7props%clr-namespace:Memory_Tools.Properties     5   	   -   5          J� Opacity$  0Q�5
   	    � Title$ Process Selector��5   	   $��334.696��6"   $��393.049��63   ���	#FF5A5A5A � WindowStyle$
 None=�6Z    � AllowsTransparency .  � Triggers 5      :� 5   
    :� RoutedEvent$ Window.Loaded��6   .[�5      �� .��5      �� .��5      W�  g� Duration$ 
00:00:0.25D�6&    �� TargetProperty$ Opacity�6<   	 W� To$ 1X�6`   5      5      5      	 � 	Resources	 5      !   Memory_Tools.ImageConverter   Conv  Template
 �� Orientation �� Path �� 	Converter��%  &	        &	      7     5   
   6   �� 5   
   .R�5      �� $
 
Horizontal=�6   .+�5      �� $��16��5      $��16��5      ��5      �� $
 Icon�8   5      �� 5      $��Center=�62   ��6   �� *Name+62   5      5       5!      .��5"      � .+�5#   
   �� -   5         ��Name$ ProcessList��5#      $
��Left=�6(   $	��257��6C   $	��Top=�6P   $	��361��6h   $��	14,35,0,0q�6t   #��[ 6�   ��6�   �� *Items+6�   �� 5$   
   -   5         ��Name$ OK��5$      $��OK��6   $
��Left=�6*   $��
14,297,0,0q�6E   $	��Top=�6Y   $	��116��6q   6}   �� 5%   
   -   5        $ Reload��5%      $��Reload��6!   $��Center=�62   $��135,297,143,0q�6O   $	��Top=�6f   $	��115��6~    J� RenderTransformOrigin$ 0.495,0.396&�6�   6�   �� 5&   
   -   5        $ Cancel��5&      $��Cancel��6!   $��Right=�62   $��
0,297,18,0q�6N   $	��Top=�6b   $	��120��6z   6�   � 5'   
   -   5        $
��Left=�5'      $��35��6*   $	��Top=�66   $	��393��6N   .+�5(      �� ���	#FF5A5A5A$
��Left=�6)   $��35��6D   ���	#FF5A5A5A$	��Top=�6c   $	��393��6{   �� 5)      $
��Left=�6   $
��Wrap=�63   $��Process Selector��6G   $	��Top=�6_   $��14,5,0,0q�6w   ���	#FF00FFEB$��15��6�   $��14(�6�   �� 5*      -   5         ��Name$ CloseButton��5*      $��x��6)   $
��Left=�65   $��
364,-6,0,0q�6P   $	��Top=�6d   
���   �$��32(�6�   $��41��6�   $��OCR A Extended)�6�    � ToolTip 5+      _� 5,      .��5-      �� $��Close��6$   5.       51      :� 52      $ Label.MouseEnter��6#   .[�53      �� .��54      �� .��55   "   �� 	 �� To$	 RedX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�56   %   $ 0:0:0.25D�57   %   58      59      5:      :� 5<      $ Label.MouseLeave��6#   .[�5=      �� .��5>      �� .��5?   "   �� $ BlackX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�5@   %   $ 0:0:0.25D�5A   %   5B      5C      5D      5F      �� 5G      -   5        $ MinimizeButton��5G      $��__��6,   $
��Left=�69   $��335,-6,0,-15q�6T   $	��Top=�6j   $��32(�6�   $��56��6�   $��OCR A Extended)�6�    5H      _� 5I      .��5J      �� $��Minimize��6$   5K       5N      :� 5O      $ Label.MouseEnter��6#   .[�5P      �� .��5Q      �� .��5R   "   �� $ YellowX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�5S   %   $ 0:0:0.25D�5T   %   5U      5V      5W      :� 5Y      $ Label.MouseLeave��6#   .[�5Z      �� .��5[      �� .��5\   "   �� $ BlackX�61   $0 *(Label.Foreground).(SolidColorBrush.Color)�5]   %   $ 0:0:0.25D�5^   %   5_      5`      5a      5c      5d      5e      5g      